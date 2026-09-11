package flow

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// DefaultStep 是未显式定时的相邻包之间的默认时间间隔(1ms)。
// flow 内部时间轴与 plan 的 standalone 默认序列共用此步长,保证缺省行为逐字节等价。
const DefaultStep = time.Millisecond

// HandshakeSteps 返回 open 握手占用的 DefaultStep 槽数:open="" 或 "handshake" 占 3
// (SYN/SYN-ACK/ACK),"none" 占 0。供 plan 阶段一算时与 Expand 的握手占位一致。
func HandshakeSteps(open string) int {
	if open == "none" {
		return 0
	}
	return 3 // "" 或 "handshake"
}

// CloseSteps 返回关闭序列占用的 DefaultStep 槽数(flowEnd 相对最后一条消息末尾的偏移):
// "fin"/"" 占 4(四次挥手),"rst" 占 1,"none" 占 0。供 plan 阶段一算时与 Expand 一致。
func CloseSteps(close string) int {
	switch close {
	case "rst":
		return 1
	case "none":
		return 0
	default:
		return 4 // "" 或 "fin"
	}
}

// SessionOf 从 flow.stack 中提取 tcp_session 的 open/close(无该层则均为 "")。
// 仅供 plan 阶段一算时用;完整栈校验仍由 Expand 的 parseFlowStack 负责。
func SessionOf(stack []scenario.Layer) (open, close string) {
	for _, l := range stack {
		if s, ok := l.Fields.(*scenario.TCPSessionFields); ok {
			return s.Open, s.Close
		}
	}
	return "", ""
}

// messagePlan 计算一条消息的分段与段间间隔:payload 字节按 segment.mss 切段,
// interval 缺省 DefaultStep(与未显式定时的历史行为逐字节等价),显式 segment.interval 覆盖。
// Expand(阶段二发包)与 MessageDuration(plan 阶段一算时)共用此函数,保证两端对
// "一条消息占多久"的认知一致——这是跨流 start_after 锚点能精确对齐的前提。
func messagePlan(m scenario.Message) ([][]byte, time.Duration, error) {
	b, err := messagePayload(m)
	if err != nil {
		return nil, 0, err
	}
	segs := split(b, segMSS(m))
	interval := DefaultStep
	if m.Segment != nil && m.Segment.Interval != nil {
		interval = m.Segment.Interval.Duration()
	}
	return segs, interval, nil
}

// MessageDuration 返回一条消息从 start 到其整组末尾(msgCursor)的占用时长:
// (n-1)*interval + 2*DefaultStep(n 段数据 + 末段后一个 DefaultStep 的对端 ACK + 一个 DefaultStep
// 作为下一条接续点)。n<=1 时为 2*DefaultStep。供 plan 阶段一预算被引消息的 msgCursor,
// 使跨流 start_after 在不发包的情况下也能算出锚点(见 scheduler)。
func MessageDuration(m scenario.Message) (time.Duration, error) {
	segs, interval, err := messagePlan(m)
	if err != nil {
		return 0, err
	}
	if len(segs) <= 1 {
		return 2 * DefaultStep, nil
	}
	return time.Duration(len(segs)-1)*interval + 2*DefaultStep, nil
}

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

type session struct {
	open  string
	close string
}

// conn 维护会话状态:src 是 TCP SYN 发起方,dst 是 SYN 接收方。
//
// flow.stack 以「整栈模板」保留:字段原样带过(含 vxlan 隧道、多层 eth/ipv4/ipv6、
// checksum/length 覆盖等),emit 只覆写派生量。覆写判据是「跟不跟连接状态走」:
// seq/ack/方向/端口逐包变,是派生量;其余是写死的字面量,原样透传。
type conn struct {
	template       []scenario.Layer // flow.stack 去掉 tcp_session,Fields 指针原样共享
	tcpIdx         int              // template 里 tcp 层的下标
	srcSeq, dstSeq uint32
	session        session
}

// MessageSchedule 是单条消息的起始时刻(由 plan 阶段一算好后传入)。
// Expand 不再为每条消息运行期解析 start_after;它只按给定的 Start 把消息整组铺到时间轴。
// nil 时按默认链式 msgCursor 接续(无跨流依赖的退化路径,逐字节等价)。
type MessageSchedule struct {
	Start time.Time
}

// noopResolve 是无跨流依赖时的占位解析器,恒返回未命中(本 flow 无 message 级 start_after)。
func noopResolve(refFlow, refMsg string) (time.Time, bool) { return time.Time{}, false }

// ResolveRef 解析 message 级 start_after 引用为绝对时刻。形如 "flow名" → 该 flow 整流结束
// (挥手后);"flow名.message_id" → 该消息整组完成(msgCursor)。仅供 Expand 的 resolve 参数
// 退化路径使用(plan 阶段一算时方案未注入 per-message schedule 时)。
type ResolveRef func(refFlow, refMsg string) (time.Time, bool)

// Expand 把一条 flow 展开成有序的、带显式时间戳的 PlannedPacket。
//
// anchor 是流的绝对起点(由 plan 算好 base+flow.offset_time 或被引时刻 + offset 传入);flow 以
// anchor 为零点排时间轴,**不再推导跨流接续**——跨流独立与跨流依赖均由 plan 在算时阶段处理好
// 后,以「该 flow 各消息的起始时刻表」注入本函数。
//
// 流内时间模型为「相对上一条消息」(链式 delta):
//   - 握手占 anchor 起(固定 DefaultStep,不参与定时);第一条消息的"上一条"= 握手完成后
//     (无握手则 = anchor),避免小 offset 与握手包撞时间。
//   - 单游标 msgCursor(= 上一条消息末尾):无显式 start 的消息 = msgCursor + offset(无 offset
//     则紧接 msgCursor)。offset>=0 故天然单调,无需夹紧;慢响应自然拖慢下一条请求。
//   - 每条消息(不论何时起)都把 msgCursor 推进到本消息整组末尾;挥手接在 msgCursor 之后
//     (传完才关)。
//   - 段间按 segment.interval 间隔(缺省 DefaultStep);对端 ACK 是伴生控制包,用 DefaultStep,
//     不被数据段节奏传染(保持"只让数据慢"的语义纯净)。
//
// flow.stack 支持 eth / vlan / ipv4|ipv6 / udp / vxlan / tcp / tcp_session 的有序层栈
// (层白名单、层序、重复由 scenario.Validate 的分段校验承载):无 vxlan 时是普通
// eth [vlan*] net tcp 会话;带一层 vxlan 时是隧道内 TCP 会话(反向包 outer eth/ip 与
// inner eth/ip 一并交换 src/dst;VNI 与 outer UDP 端口两向不变)。
//
// schedule 是该 flow 各消息的起始时刻表(按 message 声明序,一一对应)。由 plan 算时阶段
// 预先算好(跨流 start_after 已解析为绝对时刻);Expand 只照表把每条消息铺到时间轴,不再运行期
// 解析跨流依赖。nil 时退化为 resolve 回调路径(无跨流依赖时的历史行为,逐字节等价)。
//
// resolve 仅供 schedule==nil 的退化路径用:解析 message 级 start_after 引用为被引时刻(整流结束
// 或某消息 msgCursor)。nil 时用 noopResolve(本 flow 无 message 级 start_after)。
//
// 返回值:
//   - 第二个返回值是该 flow 真正结束的时刻(挥手后),供 plan 解析裸 flow 名引用(整流结束)。
//   - 第三个返回值是 message_id → 该消息整组完成时刻(msgCursor)的映射,仅收录显式设了
//     message_id 的消息;供 plan 解析其它 flow / message 的 start_after 引用。空(无具名消息)时为 nil。
func Expand(f scenario.FlowSpec, anchor time.Time, schedule []MessageSchedule, resolve ResolveRef) ([]scenario.PlannedPacket, time.Time, map[string]time.Time, error) {
	if len(schedule) > 0 && len(schedule) != len(f.Messages) {
		return nil, time.Time{}, nil, fmt.Errorf("schedule 长度 %d 与消息数 %d 不符", len(schedule), len(f.Messages))
	}
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
	for mi, m := range f.Messages {
		b, err := messagePayload(m)
		if err != nil {
			return nil, time.Time{}, msgids, err
		}
		// 本消息起始:
		//   - schedule 非空(plan 算时方案):start 来自算时阶段给出的绝对时刻(已含 start_after
		//     解析与 offset_time),Expand 不再推导、不再叠加 offset(否则会重复)。
		//   - 退化路径(无 schedule):默认 = 上一条末尾 + offset;message 级 start_after 把参照点
		//     从 msgCursor 改为被引时刻(整流结束或某消息 msgCursor),再 + offset_time。
		start := msgCursor
		if len(schedule) > 0 {
			start = schedule[mi].Start
		} else {
			if m.StartAfter != "" {
				refFlow, refMsg, _ := scenario.SplitStartAfter(m.StartAfter)
				got, ok := resolve(refFlow, refMsg)
				if !ok {
					// 被引时刻未解析到:plan 在展开前应保证被引 flow 已展开,此处不应到达。
					return nil, time.Time{}, msgids, fmt.Errorf("message 的 start_after %q 未能解析(被引 flow/message 未展开)", m.StartAfter)
				}
				start = got
			}
			if m.OffsetTime != nil {
				start = start.Add(m.OffsetTime.Duration())
			}
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

// parseFlowStack 保留整栈模板并提取会话状态。不做字段级解构:各层 Fields 指针原样进模板,
// emit 时逐层浅拷贝并覆写派生量。层白名单/层序/必备层校验在 scenario.Validate(validateFlow);
// 这里只留一条展开必需的不变式:必须有 tcp 层(要定位 tcpIdx)。
func parseFlowStack(stack []scenario.Layer) (*conn, error) {
	c := &conn{tcpIdx: -1}
	for _, l := range stack {
		if l.Type == "tcp_session" {
			if s, ok := l.Fields.(*scenario.TCPSessionFields); ok {
				c.session = session{open: s.Open, close: s.Close}
			}
			continue
		}
		if l.Type == "tcp" {
			c.tcpIdx = len(c.template)
			if f, ok := l.Fields.(*scenario.TCPFields); ok {
				c.srcSeq, c.dstSeq = f.ClientISN, f.ServerISN
			}
		}
		c.template = append(c.template, l)
	}
	if c.tcpIdx == -1 {
		return nil, fmt.Errorf("flow.stack 需要 tcp 层")
	}
	return c, nil
}

// emit 发一个方向的段:对模板逐层浅拷贝,覆写派生量(方向端点交换、TCP 状态字段),
// 尾部追加 payload 字节。模板只被读取不回写;各层 Fields 指针跨包共享是安全的
// (builder 各 build* 只读字段,不改 *Fields;未写方向 VID 的 vlan 即共享同一指针)。
// 层数也可能随方向变化:写了方向化 VID 的 vlan 层在缺该向 VID 时整层摘除
// (上行带标签下行不带 / 上行双层下行单层),摘除只影响本次重建的 stack。
func (c *conn) emit(from side, flags []string, chunk []byte, summaryLayers []string) scenario.Packet {
	reverse := from == sideDst

	tcpF := c.template[c.tcpIdx].Fields.(*scenario.TCPFields)
	tcp := *tcpF // 浅拷贝
	tcp.Seq, tcp.Ack = c.seqAck(from, flags, len(chunk))
	tcp.Flags = flags
	if hasFlag(flags, "SYN") && tcpF.MSS != nil {
		tcp.MSS = tcpF.MSS
	} else {
		tcp.MSS = nil // 非 SYN 包必须显式清掉(浅拷贝会把模板的 MSS 带过来)
	}
	if reverse {
		tcp.SPort, tcp.DPort = tcp.DPort, tcp.SPort
	}

	stack := make([]scenario.Layer, 0, len(c.template)+1)
	for i, l := range c.template {
		cp := l // 浅拷贝:Type 不变,Fields 指针默认共享
		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			eth := *f
			if reverse {
				eth.Src, eth.Dst = eth.Dst, eth.Src
			}
			cp.Fields = &eth
		case *scenario.IPv4Fields:
			ip := *f
			if reverse {
				ip.Src, ip.Dst = ip.Dst, ip.Src
			}
			cp.Fields = &ip
		case *scenario.IPv6Fields:
			ip := *f
			if reverse {
				ip.Src, ip.Dst = ip.Dst, ip.Src
			}
			cp.Fields = &ip
		case *scenario.VLANFields:
			// 方向化 VID:上行取 src_vid、下行取 dst_vid;该向缺省(nil)= 整层摘除。
			// 经典 vid 写法(两向字段皆 nil)保持原路径:Fields 指针原样共享。
			if f.SrcVID != nil || f.DstVID != nil {
				vid := f.SrcVID
				if reverse {
					vid = f.DstVID
				}
				if vid == nil {
					continue // 该方向不带这层标签
				}
				v := *f
				v.VID, v.SrcVID, v.DstVID = *vid, nil, nil
				cp.Fields = &v
			}
		case *scenario.TCPFields:
			if i == c.tcpIdx {
				cp.Fields = &tcp
			}
		}
		stack = append(stack, cp)
	}
	if len(chunk) > 0 {
		stack = append(stack, scenario.Layer{
			Type:   "payload_hex",
			Fields: scenario.PayloadHex("0x" + hex.EncodeToString(chunk)),
		})
	}
	return scenario.Packet{Stack: stack, SummaryLayers: summaryLayers}
}

// seqAck 取当前方向的 seq/ack 并推进状态:seq 前进量 = payload 字节 + SYN(1) + FIN(1);
// 纯 ACK/RST 不前进。ack = 对端当前 seq。
func (c *conn) seqAck(from side, flags []string, payloadLen int) (seq, ack *uint32) {
	var s, a uint32
	if from == sideSrc {
		s, a = c.srcSeq, c.dstSeq
	} else {
		s, a = c.dstSeq, c.srcSeq
	}
	adv := uint32(payloadLen)
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
	return &s, &a
}

func messagePayload(m scenario.Message) ([]byte, error) {
	if len(m.Stack) == 0 {
		return nil, fmt.Errorf("message.stack 需至少一个 payload 生产层")
	}
	// 多 payload 生产层按栈声明顺序(外→内)依次拼接,与 serializeStack 对 standalone
	// packet 多 payload 层的拼接语义一致;拼接后的总字节照常按 segment.mss 切段。
	var out []byte
	for k, l := range m.Stack {
		b, err := builder.PayloadBytes(l)
		if err != nil {
			return nil, fmt.Errorf("message.stack[%d]: %w", k, err)
		}
		out = append(out, b...)
	}
	return out, nil
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
