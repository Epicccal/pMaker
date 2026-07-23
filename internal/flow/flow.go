package flow

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// ResolveRef 解析 start_after 引用为绝对时刻。形如 "flow名" → 该 flow 整流结束(挥手后);
// "flow名.message_id" → 该消息整组完成(msgCursor)。refFlow/refMsg 由 scenario.SplitStartAfter
// 拆出。msg=="" 表示引用整流结束,取 flowEnd[refFlow];否则取 msgCursors[refFlow][refMsg]。
// 未解析到返回 (zero,false)。
type ResolveRef func(refFlow, refMsg string) (time.Time, bool)

// noopResolve 是无跨流依赖时的占位解析器,恒返回未命中(本 flow 无 message 级 start_after)。
func noopResolve(refFlow, refMsg string) (time.Time, bool) { return time.Time{}, false }

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
// anchor 是流的绝对起点(由 plan 算好 base+flow.offset_time 或 base 传入);flow 以 anchor
// 为零点排时间轴,**不再推导跨流接续**——跨流独立由 plan 保证(每条 flow 各自从其 anchor 起步,
// 互不依赖、可并行;无 offset 的 flow 在 base 起步)。
//
// 流内时间模型为「相对上一条消息」(链式 delta):
//   - 握手占 anchor 起(固定 DefaultStep,不参与定时);第一条消息的"上一条"= 握手完成后
//     (无握手则 = anchor),避免小 offset 与握手包撞时间。
//   - 单游标 msgCursor(= 上一条消息末尾):每条消息 start = msgCursor + offset(无 offset 则紧接
//     msgCursor)。offset>=0 故天然单调,无需夹紧;慢响应自然拖慢下一条请求(正常非流水线 HTTP)。
//   - 每条消息(不论有无 offset)都把 msgCursor 推进到本消息整组末尾;挥手接在 msgCursor 之后
//     (传完才关)。
//   - 段间按 segment.interval 间隔(缺省 DefaultStep);对端 ACK 是伴生控制包,用 DefaultStep,
//     不被数据段节奏传染(保持"只让数据慢"的语义纯净)。
//
// 当前 flow.stack 支持 eth/ipv4/tcp/tcp_session;VLAN/GRE 等会话封装后续扩展。
//
// 返回值:
//   - 第二个返回值是该 flow 真正结束的时刻(挥手后),供 plan 解析裸 flow 名引用(整流结束)。
//   - 第三个返回值是 message_id → 该消息整组完成时刻(msgCursor)的映射,仅收录显式设了
//     message_id 的消息;供 plan 解析其它 flow / message 的 start_after 引用。空(无具名消息)时为 nil。
//
// resolve 解析 message 级 start_after 引用为被引时刻(整流结束或某消息 msgCursor)。
// 当某条 message 设了 start_after 时,其起点 = resolve(被引)+ offset_time(缺省 0 紧接),
// 取代默认的"上一条消息末尾";之后仍以本消息整组末尾推进 msgCursor。nil 时用 noopResolve
// (本 flow 无 message 级 start_after,行为与历史逐字节等价)。
func Expand(f scenario.FlowSpec, anchor time.Time, resolve ResolveRef) ([]scenario.PlannedPacket, time.Time, map[string]time.Time, error) {
	if resolve == nil {
		resolve = noopResolve
	}
	c, err := parseFlowStack(f.Stack)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	var out []scenario.PlannedPacket
	var msgids map[string]time.Time // message_id → 本消息整组完成时刻(msgCursor)
	cursor := anchor                // 流内时间游标:每个包占一个槽,默认递进 DefaultStep

	// 三次握手(SYN / SYN,ACK 携带通告 MSS)
	if c.session.open == "" || c.session.open == "handshake" {
		out = appendAt(out, c.emit(sideSrc, []string{"SYN"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideDst, []string{"SYN", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
		out = appendAt(out, c.emit(sideSrc, []string{"ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
	}

	// message.offset_time 相对"上一条消息的末尾":每条消息 = 上一条末尾 + offset(无 offset 则紧接)。
	// 第一条消息的"上一条"= 握手完成后(无握手则 = 流锚 anchor),避免小 offset 与握手包撞时间。
	// offset>=0 故天然单调,无需夹紧。
	msgCursor := cursor // 单游标:上一条消息末尾;首条以握手完成后(无握手则 anchor)为参照

	// 应用层消息:按 segment.mss 切段发送,对端按 per-message 回一个 ACK
	for _, m := range f.Messages {
		b, err := messagePayload(m)
		if err != nil {
			return nil, time.Time{}, msgids, err
		}
		// 本消息起始:默认 = 上一条末尾 + offset(无 offset 紧接 msgCursor)。
		// message 级 start_after 把参照点从 msgCursor 改为被引时刻(整流结束或某消息 msgCursor),
		// 再 + offset_time。offset>=0 故天然单调。
		start := msgCursor
		if m.StartAfter != "" {
			refFlow, refMsg, _ := scenario.SplitStartAfter(m.StartAfter)
			got, ok := resolve(refFlow, refMsg)
			if !ok {
				// 被引时刻未解析到:plan 在展开前应保证被引 flow 已展开,此处不应到达。
				// 落到 msgCursor(默认行为)是安全的退化,但提示用户引用未生效。
				return nil, time.Time{}, msgids, fmt.Errorf("message 的 start_after %q 未能解析(被引 flow/message 未展开)", m.StartAfter)
			}
			start = got
		}
		if m.OffsetTime != nil {
			start = start.Add(m.OffsetTime.Duration())
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
		msgCursor = end           // 每条消息都推进游标(顺序语义)
		// 收录具名消息的整组完成时刻(msgCursor),供 plan 解析 start_after 引用。
		if m.MessageID != "" {
			if msgids == nil {
				msgids = map[string]time.Time{}
			}
			msgids[m.MessageID] = msgCursor
		}
	}

	// 关闭:默认四次挥手;rst 表示对端(dst)单包中断连接。挥手接 msgCursor(最后一条消息末尾)。
	cursor = msgCursor
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
	case "rst":
		out = appendAt(out, c.emit(sideDst, []string{"RST", "ACK"}, nil, nil), cursor)
		cursor = cursor.Add(DefaultStep)
	}
	return out, cursor, msgids, nil
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
