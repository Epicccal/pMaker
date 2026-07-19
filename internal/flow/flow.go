package flow

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

type side int

const (
	sideSrc side = iota
	sideDst
)

func (s side) peer() side {
	if s == sideSrc {
		return sideDst
	}
	return sideSrc
}

type endpoint struct {
	mac  string
	ip   string
	port uint16
}

type session struct {
	open  string
	close string
}

// conn 维护会话状态:src 是 TCP SYN 发起方,dst 是 SYN 接收方。
type conn struct {
	src, dst       endpoint
	ttl            *uint8
	srcSeq, dstSeq uint32
	mss            *uint16
	session        session
}

// DefaultStep 是未显式定时的相邻包之间的默认时间间隔(1ms)。
// flow 内部时间轴与 plan 的 standalone 默认序列共用此步长,保证缺省行为逐字节等价。
const DefaultStep = time.Millisecond

// Expand 把一条 flow 展开成有序的、带显式时间戳的 PlannedPacket。
//
// anchor 是流起始锚(base + flow.offset_time,或接续默认游标),由 plan 层算好传入;
// flow 以 anchor 为零点排时间轴:握手占 anchor 起(固定 DefaultStep,不参与定时),各消息按
// offset_time 锚定或接续——其零点是"握手完成后"(无握手则 = anchor),段间按 segment.interval 间隔。
// 未显式定时时每包间隔 DefaultStep,与历史行为逐字节等价。
//
// 接续语义:无 offset 的消息接续「正常时序游标」msgCursor(上一条无 offset 消息的末尾);
// 带 offset 的消息把自己钉到 msgAnchor+offset,但**不推进 msgCursor**——用 offset 制造的
// 插队/乱序只影响它自己,不污染后续无 offset 消息的接续点(避免"插队劫持接续")。挥手接在
// 最后一个实际发出的包之后(lastEnd),保证数据传完再关。详见消息循环内注释。
//
// 当前 flow.stack 支持 eth/ipv4/tcp/tcp_session;VLAN/GRE 等会话封装后续扩展。
//
// 第二个返回值 normalEnd 是"按正常时序 flow 完整结束后的接续点",供 plan 推进默认游标——
// 避免某条 flow 内部的 message.offset_time 插队消息把下一条无 offset flow 拖到插队时刻之后
// (跨流劫持)。normalEnd 由 normalCursor 推导:每条消息(不论有无 offset)都按其正常持续时长
// 占位,但 offset 把消息"钉到别处"的时间扰动(如 +100s)不计入——即插队消息贡献正常占位,
// 不贡献延迟。无 offset 时 normalEnd == 末包接续点,行为逐字节不变。
func Expand(f scenario.FlowSpec, anchor time.Time) ([]scenario.PlannedPacket, time.Time, error) {
	c, err := parseFlowStack(f.Stack)
	if err != nil {
		return nil, time.Time{}, err
	}
	var out []scenario.PlannedPacket
	cursor := anchor // 流内时间游标:每个包占一个槽,默认递进 DefaultStep

	// 三次握手(SYN / SYN,ACK 携带通告 MSS)
	if c.session.open == "" || c.session.open == "handshake" {
		out = appendAt(out, c.emit(sideSrc, []string{"SYN"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideDst, []string{"SYN", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideSrc, []string{"ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
	}

	// message.offset_time 的零点是"握手完成后"(无握手则 = 流锚 anchor):握手固定
	// DefaultStep 不参与定时,数据通信的偏移从握手结束算起,避免小 offset 与握手包撞时间。
	msgAnchor := cursor

	// msgCursor 是"无 offset 消息"的接续游标:每条无 offset 消息从它起排,排完后推进到
	// 该消息整组末尾。带 offset 的消息只把自己钉到 msgAnchor+offset,不推进 msgCursor——
	// 这样用 offset 制造的插队/乱序不会污染后续无 offset 消息的接续点。真实 TCP 里一条
	// 字节流的发送节奏由本端已发数据决定,显式插队不该拖走本端下一条消息的发送时刻。
	msgCursor := msgAnchor
	// normalCursor 是"按正常时序(每条消息都占位)flow 结束的接续点",供跨 flow 接续。
	// 与 msgCursor 的区别:msgCursor 只被无 offset 消息推进(flow 内部下一条消息接续用,
	// 插队不占槽——避免插队劫持本端下一条消息);normalCursor 被所有消息推进(跨 flow 接续用,
	// 插队占正常槽——下一条 flow 接本 flow 完整正常长度之后)。两者都不含 offset 的"时间扰动"
	// (offset 只改发包时刻,不改正常持续时长)。
	normalCursor := msgAnchor
	// lastEnd 记录所有消息实际末尾的最大值,挥手从这里起:无论中间是否有 offset 插队,
	// 挥手都接在最后一个实际发出的包之后,保证"传完才关",不被插队消息拉偏。
	lastEnd := msgAnchor

	// 应用层消息:按 segment.mss 切段发送,对端按 per-message 回一个 ACK
	for _, m := range f.Messages {
		b, err := messagePayload(m)
		if err != nil {
			return nil, time.Time{}, err
		}
		// 本消息起始:有 offset 钉到 msgAnchor+offset(插队,不碰 msgCursor);
		// 无 offset 接续 msgCursor(正常时序)。
		start := msgCursor
		if m.OffsetTime != nil {
			start = msgAnchor.Add(m.OffsetTime.Duration())
		}
		// 段间间隔:缺省 DefaultStep(与历史等价),显式 interval 覆盖。
		// interval 只作用于数据段(规避节奏);对端 ACK 是伴生控制包,用 DefaultStep,
		// 不被数据段的慢速节奏传染——保持"只让数据慢"的语义纯净。
		interval := DefaultStep
		if m.Segment != nil && m.Segment.Interval != nil {
			interval = m.Segment.Interval.Duration()
		}
		from := sideOf(m.From)
		summaryLayers := scenario.SummaryLayerNames(m.Stack)
		t := start
		var lastSeg time.Time
		for _, seg := range split(b, segMSS(m)) {
			out = appendAt(out, c.emit(from, []string{"PSH", "ACK"}, seg, summaryLayers), t)
			lastSeg = t
			t = t.Add(interval)
		}
		// 对端 ACK 紧跟最后一段一个 DefaultStep(简化模型,非真实 delayed ACK)。
		t = lastSeg.Add(DefaultStep)
		out = appendAt(out, c.emit(from.peer(), []string{"ACK"}, nil, nil), t)
		end := t.Add(DefaultStep) // 本消息整组末尾(ACK 之后 +1ms,即下一条接续点)
		// 无 offset 消息推进接续游标;带 offset 的插队消息不推进——插队只影响自己,
		// 不污染后续无 offset 消息的接续。
		if m.OffsetTime == nil {
			msgCursor = end
		}
		// normalCursor 始终推进:按本消息正常持续时长(end-start,与 offset 无关)累加,
		// 供跨 flow 接续。offset 只把消息钉到别处,不改变它在该 flow 正常时序里的占位。
		normalCursor = normalCursor.Add(end.Sub(start))
		if end.After(lastEnd) {
			lastEnd = end
		}
	}

	// 关闭:默认四次挥手;rst 表示对端(dst)单包中断连接。挥手接 lastEnd(最后一个实际
	// 发出的包之后),保证数据传完再关连接。
	//
	// normalEnd 是"按正常时序 flow 完整结束后的接续点",供 plan 推进默认游标。
	// = normalCursor(所有消息按正常占位累加的接续点末尾) + 挥手占用的步长。offset 的时间扰动
	// 不计入 normalCursor,故 normalEnd 不含插队延迟——下一条 flow 接续在"正常结束"之后,
	// 插队包作为游离包(在 msgAnchor+offset)独立存在。
	normalEnd := normalCursor
	cursor = lastEnd
	switch c.session.close {
	case "", "fin":
		out = appendAt(out, c.emit(sideSrc, []string{"FIN", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideDst, []string{"ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideDst, []string{"FIN", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideSrc, []string{"ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		normalEnd = normalEnd.Add(4 * DefaultStep)
	case "rst":
		out = appendAt(out, c.emit(sideDst, []string{"RST", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		normalEnd = normalEnd.Add(DefaultStep)
	}
	return out, normalEnd, nil
}

// appendAt 把一个 stack 包包装成带时间戳的 PlannedPacket 追加到 out。
func appendAt(out []scenario.PlannedPacket, p scenario.Packet, t time.Time) []scenario.PlannedPacket {
	return append(out, scenario.PlannedPacket{Packet: p, Time: t})
}

func parseFlowStack(stack []scenario.Layer) (*conn, error) {
	c := &conn{}
	for _, l := range stack {
		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			c.src.mac, c.dst.mac = f.Src, f.Dst
		case *scenario.IPv4Fields:
			c.src.ip, c.dst.ip = f.Src, f.Dst
			c.ttl = f.TTL
		case *scenario.TCPFields:
			c.src.port, c.dst.port = f.SPort, f.DPort
			c.srcSeq, c.dstSeq = f.ClientISN, f.ServerISN
			c.mss = f.MSS
		case *scenario.TCPSessionFields:
			c.session = session{open: f.Open, close: f.Close}
		default:
			return nil, fmt.Errorf("flow.stack 暂不支持 %q", l.Type)
		}
	}
	if c.src.mac == "" || c.dst.mac == "" || c.src.ip == "" || c.dst.ip == "" || c.src.port == 0 || c.dst.port == 0 {
		return nil, fmt.Errorf("flow.stack 需要 eth/src-dst、ipv4/src-dst、tcp/sport-dport")
	}
	return c, nil
}

// emit 发一个方向的段:填 seq/ack、推进状态,产出一个 stack 包。
func (c *conn) emit(from side, flags []string, chunk []byte, summaryLayers []string) scenario.Packet {
	var seq, ack uint32
	if from == sideSrc {
		seq, ack = c.srcSeq, c.dstSeq
	} else {
		seq, ack = c.dstSeq, c.srcSeq
	}

	// seq 前进量 = payload 字节 + SYN(1) + FIN(1);纯 ACK/RST 不前进。
	adv := uint32(len(chunk))
	if hasFlag(flags, "SYN") {
		adv++
	}
	if hasFlag(flags, "FIN") {
		adv++
	}
	if from == sideSrc {
		c.srcSeq += adv
	} else {
		c.dstSeq += adv
	}

	src, dst := c.src, c.dst
	if from == sideDst {
		src, dst = c.dst, c.src
	}

	tcp := &scenario.TCPFields{
		SPort: src.port,
		DPort: dst.port,
		Flags: flags,
		Seq:   &seq,
		Ack:   &ack,
	}
	if hasFlag(flags, "SYN") && c.mss != nil {
		tcp.MSS = c.mss
	}

	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: src.mac, Dst: dst.mac}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: src.ip, Dst: dst.ip, TTL: c.ttl}},
		{Type: "tcp", Fields: tcp},
	}
	if len(chunk) > 0 {
		stack = append(stack, scenario.Layer{
			Type:   "payload_hex",
			Fields: scenario.PayloadHex("0x" + hex.EncodeToString(chunk)),
		})
	}
	return scenario.Packet{Stack: stack, SummaryLayers: summaryLayers}
}

func messagePayload(m scenario.Message) ([]byte, error) {
	if len(m.Stack) != 1 {
		return nil, fmt.Errorf("message.stack 当前需恰好一个 payload 生产层")
	}
	return builder.PayloadBytes(m.Stack[0])
}

func segMSS(m scenario.Message) int {
	if m.Segment != nil {
		return m.Segment.MSS
	}
	return 0
}

// split 按 mss 把字节切成多段;mss<=0 或不足一段时整条返回。
func split(b []byte, mss int) [][]byte {
	if mss <= 0 || len(b) <= mss {
		return [][]byte{b}
	}
	var segs [][]byte
	for len(b) > mss {
		segs = append(segs, b[:mss])
		b = b[mss:]
	}
	return append(segs, b)
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func sideOf(s string) side {
	if s == "dst" {
		return sideDst
	}
	return sideSrc
}
