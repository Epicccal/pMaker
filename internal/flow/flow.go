package flow

import (
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// DefaultStep 是未显式定时的相邻包之间的默认时间间隔(1ms)。
// flow 内部时间轴与 plan 的 standalone 默认序列共用此步长,保证缺省行为逐字节等价。
const DefaultStep = time.Millisecond

// Transport 是 flow 会话的传输层种类。UDP 无连接,不维护 seq/ack、不补握手/挥手;
// 两者差异集中在 transportFields 与 Expand 首尾,不抽 interface —— 只有两个实现、
// 差异集中,本仓库既有风格是表 + switch(layerDecoders / flowLayerRank / imapCommands)。
// 第三种传输(SCTP)出现时再抽。
type Transport int

const (
	TransportTCP Transport = iota
	TransportUDP
)

// Profile 描述一条 flow 的时间形状:握手/挥手/每消息尾部各占多少 DefaultStep 槽。
// plan 阶段一算时与 Expand 阶段二发包都从这里取,保证两端对 msgCursor 的认知一致
// (MessageDuration 与 Expand 给出同一个答案是跨流 start_after 锚点精确对齐的前提)。
//
// 时间轴(槽 = DefaultStep,箭头各进一槽;段间按 segment.interval,缺省 DefaultStep):
//
//	anchor ──► SYN ──► SYN,ACK ──► ACK ──► seg1 ──► seg2 ──► seg3 ──► 对端ACK ──► msgCursor ──► FIN,ACK ──► ...
//	           └────── HandshakeSteps=3 ──────┘                            └─TailSteps=2─┘ └─ CloseSteps=4 ─┘
//
// 消息占用 = (段数-1)·interval + TailSteps·DefaultStep(= MessageDuration);
// flowEnd = 末条 msgCursor + CloseSteps·DefaultStep。UDP 三者全零、TailSteps=1:
// 无握手/挥手/对端 ACK,每消息恰一段,msgCursor = 末段 + 1 槽,flowEnd = 末条 msgCursor。
type Profile struct {
	Transport      Transport
	HandshakeSteps int // TCP: open="none" 为 0,否则 3;UDP: 0
	CloseSteps     int // TCP: fin=4 / rst=1 / none=0;UDP: 0
	TailSteps      int // 末段后到 msgCursor 的槽数:TCP=2(对端 ACK + 接续点),UDP=1(接续点)
}

// ProfileOf 从 flow.stack 推导时间形状:有 udp_session 层 → UDP(全零步数,TailSteps=1);
// 否则按 tcp_session 的 open/close(缺省 handshake/fin)推导 TCP 形状。
// plan 的 scheduler 与 parseFlowStack 共用此推导,不各自维护一份 open/close 解析。
func ProfileOf(stack []scenario.Layer) Profile {
	for _, l := range stack {
		if _, ok := l.Fields.(*scenario.UDPSessionFields); ok {
			return Profile{Transport: TransportUDP, TailSteps: 1}
		}
	}
	open, close := sessionOf(stack)
	return Profile{
		Transport:      TransportTCP,
		HandshakeSteps: handshakeSteps(open),
		CloseSteps:     closeSteps(close),
		TailSteps:      2,
	}
}

// handshakeSteps 返回 open 握手占用的 DefaultStep 槽数:open="" 或 "handshake" 占 3
// (SYN/SYN-ACK/ACK),"none" 占 0。供 ProfileOf 与 Expand 的握手占位一致。
func handshakeSteps(open string) int {
	if open == "none" {
		return 0
	}
	return 3 // "" 或 "handshake"
}

// closeSteps 返回关闭序列占用的 DefaultStep 槽数(flowEnd 相对最后一条消息末尾的偏移):
// "fin"/"" 占 4(四次挥手),"rst" 占 1,"none" 占 0。供 ProfileOf 与 Expand 一致。
func closeSteps(close string) int {
	switch close {
	case "rst":
		return 1
	case "none":
		return 0
	default:
		return 4 // "" 或 "fin"
	}
}

// sessionOf 从 flow.stack 中提取 tcp_session 的 open/close(无该层则均为 "")。
// 供 ProfileOf 用;完整栈校验仍由 scenario.Validate 的分段校验承载。
func sessionOf(stack []scenario.Layer) (open, close string) {
	for _, l := range stack {
		if s, ok := l.Fields.(*scenario.TCPSessionFields); ok {
			return s.Open, s.Close
		}
	}
	return "", ""
}

// messagePlan 计算一条消息的分段与段间间隔:payload 字节按 segment.mss 切段,
// interval 缺省 DefaultStep,显式 segment.interval 覆盖。UDP 会话无视 segment
// (校验阶段已禁;这里不切段是防御纵深,保证算时与发包都不会把数据报切碎)。
// Expand(阶段二发包)与 MessageDuration(plan 阶段一算时)共用此函数,保证两端对
// "一条消息占多久"的认知一致——这是跨流 start_after 锚点能精确对齐的前提。
func messagePlan(m scenario.Message, p Profile) ([][]byte, time.Duration, error) {
	b, err := messagePayload(m)
	if err != nil {
		return nil, 0, err
	}
	interval := DefaultStep
	mss := segMSS(m)
	if p.Transport == TransportUDP {
		mss, m.Segment = 0, nil
	} else if m.Segment != nil && m.Segment.Interval != nil {
		interval = m.Segment.Interval.Duration()
	}
	return split(b, mss), interval, nil
}

// MessageDuration 返回一条消息从 start 到其整组末尾(msgCursor)的占用时长:
// (n-1)*interval + TailSteps*DefaultStep。TCP 下 TailSteps=2(n 段数据 + 末段后一个
// DefaultStep 的对端 ACK + 一个 DefaultStep 作为下一条接续点);UDP 下 segment 被禁、
// n 恒为 1、无对端 ACK,TailSteps=1(仅接续点)。供 plan 阶段一预算被引消息的 msgCursor,
// 使跨流 start_after 在不发包的情况下也能算出锚点(见 scheduler)。
func MessageDuration(m scenario.Message, p Profile) (time.Duration, error) {
	segs, interval, err := messagePlan(m, p)
	if err != nil {
		return 0, err
	}
	if len(segs) <= 1 {
		return time.Duration(p.TailSteps) * DefaultStep, nil
	}
	return time.Duration(len(segs)-1)*interval + time.Duration(p.TailSteps)*DefaultStep, nil
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

// conn 维护会话状态:src 是 TCP SYN 发起方,dst 是 SYN 接收方;UDP 会话下 src 即
// 首条消息可能来自的声明端点,方向语义一致(反向 = 端点互换)。
//
// flow.stack 以「整栈模板」保留:字段原样带过(含 vxlan 隧道、多层 eth/ipv4/ipv6、
// checksum/length 覆盖等),emit 只覆写派生量。覆写判据是「跟不跟连接状态走」:
// seq/ack/方向/端口逐包变,是派生量;其余是写死的字面量,原样透传。
type conn struct {
	template       []scenario.Layer // flow.stack 去掉会话层,Fields 指针原样共享
	transport      Transport        // 会话传输层种类(TCP 维护 seq/ack;UDP 只反转端口)
	transportIdx   int              // template 里会话传输层(tcp/udp)的下标
	srcSeq, dstSeq uint32           // 仅 TCP 读写;UDP 恒为 0
	session        session
	profile        Profile
}

// MessageSchedule 是单条消息的起始时刻(由 plan 阶段一算好后传入)。
// Expand 不运行期解析 start_after;只按给定的 Start 把消息整组铺到时间轴。
// nil(整个 schedule 为空)时按默认链式 msgCursor 接续,不支持跨流 start_after。
type MessageSchedule struct {
	Start time.Time
}

// Expand 把一条 flow 展开成有序的、带显式时间戳的 PlannedPacket。
//
// anchor 是流的绝对起点(由 plan 算好 base+flow.offset_time 或被引时刻 + offset 传入);flow 以
// anchor 为零点排时间轴,**不再推导跨流接续**——跨流独立与跨流依赖均由 plan 在算时阶段处理好
// 后,以「该 flow 各消息的起始时刻表」注入本函数。
//
// 流内时间模型为「相对上一条消息」(链式 delta):
//   - TCP 握手占 anchor 起(固定 DefaultStep,不参与定时);第一条消息的"上一条"= 握手完成后
//     (无握手则 = anchor),避免小 offset 与握手包撞时间。UDP 无握手,首条消息直接以 anchor 为参照。
//   - 单游标 msgCursor(= 上一条消息末尾):无显式 start 的消息 = msgCursor + offset(无 offset
//     则紧接 msgCursor)。offset>=0 故天然单调,无需夹紧;慢响应自然拖慢下一条请求。
//   - 每条消息(不论何时起)都把 msgCursor 推进到本消息整组末尾;挥手接在 msgCursor 之后
//     (传完才关)。UDP 无挥手,msgCursor 即流末尾。
//   - 段间按 segment.interval 间隔(缺省 DefaultStep);对端 ACK 是伴生控制包,用 DefaultStep,
//     不被数据段节奏传染(保持"只让数据慢"的语义纯净)。
//
// flow.stack 支持 eth / vlan / ipv4|ipv6 / udp / vxlan / tcp / tcp_session / udp_session 的
// 有序层栈(层白名单、层序、重复由 scenario.Validate 的分段校验承载):无 vxlan 时是普通
// eth [vlan*] net transport 会话(TCP 或 UDP);带一层 vxlan 时是隧道内会话(反向包 outer
// eth/ip 与 inner eth/ip 一并交换 src/dst;VNI 与 outer UDP 端口两向不变)。UDP 会话
// (udp_session)不补握手/挥手、不插对端 ACK,每条消息恰一个数据报,方向反转只交换
// 会话 UDP 层端口。
//
// schedule 是该 flow 各消息的起始时刻表(按 message 声明序,一一对应)。由 plan 算时阶段
// 预先算好(跨流 start_after 已解析为绝对时刻);Expand 只照表把每条消息铺到时间轴,不再运行期
// 解析跨流依赖。nil 时按默认链式 msgCursor 接续(不支持跨流 start_after)。
//
// 返回值:
//   - 第二个返回值是该 flow 真正结束的时刻(TCP = 挥手后;UDP = 末条消息 msgCursor),
//     供 plan 解析裸 flow 名引用(整流结束)。
//   - 第三个返回值是 message_id → 该消息整组完成时刻(msgCursor)的映射,仅收录显式设了
//     message_id 的消息;供 plan 解析其它 flow / message 的 start_after 引用。空(无具名消息)时为 nil。
func Expand(f scenario.FlowSpec, anchor time.Time, schedule []MessageSchedule) ([]scenario.PlannedPacket, time.Time, map[string]time.Time, error) {
	if len(schedule) > 0 && len(schedule) != len(f.Messages) {
		return nil, time.Time{}, nil, fmt.Errorf("schedule 长度 %d 与消息数 %d 不符", len(schedule), len(f.Messages))
	}
	c, err := parseFlowStack(f.Stack)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	var out []scenario.PlannedPacket
	var msgids map[string]time.Time // message_id → 本消息整组完成时刻(msgCursor)
	cursor := anchor                // 流内时间游标:每个包占一个槽,默认递进 DefaultStep

	// 三次握手(SYN / SYN,ACK 携带通告 MSS);UDP 无握手,跳过。
	if c.transport == TransportTCP && (c.session.open == "" || c.session.open == "handshake") {
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

	// 应用层消息:TCP 按 segment.mss 切段发送、对端按 per-message 回一个 ACK;
	// UDP 不切段(segment 在校验阶段被禁)、无对端 ACK,每条消息恰一个数据报。
	for mi, m := range f.Messages {
		segs, interval, err := messagePlan(m, c.profile)
		if err != nil {
			return nil, time.Time{}, msgids, err
		}
		// 本消息起始:
		//   - schedule 非空(plan 注入):start 来自算时阶段给出的绝对时刻(已含 start_after
		//     解析与 offset_time),Expand 不再推导、不再叠加 offset(否则会重复)。
		//   - schedule 为空:start = 上一条末尾 + offset_time(无 offset 则紧接 msgCursor)。
		//     message 级 start_after 由 plan 算时阶段解析后经 schedule 注入,schedule 为空时不支持跨流引用。
		start := msgCursor
		if len(schedule) > 0 {
			start = schedule[mi].Start
		} else if m.OffsetTime != nil {
			start = start.Add(m.OffsetTime.Duration())
		}
		from := sideOf(m.From)
		summaryLayers := scenario.SummaryLayerNames(m.Stack)
		t := start
		var lastSeg time.Time
		for _, seg := range segs {
			flags := []string{"PSH", "ACK"}
			if c.transport == TransportUDP {
				flags = nil
			}
			out = appendAt(out, c.emit(from, flags, seg, summaryLayers), t)
			lastSeg = t
			t = t.Add(interval)
		}
		// TCP:对端 ACK 紧跟最后一段一个 DefaultStep(简化模型,非真实 delayed ACK);
		// 随后 +1 个 DefaultStep 作为下一条接续点(msgCursor)。
		// UDP:无 ACK,末段后 +1 个 DefaultStep 即 msgCursor。
		end := lastSeg.Add(time.Duration(c.profile.TailSteps) * DefaultStep)
		if c.transport == TransportTCP {
			out = appendAt(out, c.emit(from.peer(), []string{"ACK"}, nil, nil), end.Add(-DefaultStep))
		}
		msgCursor = end // 每条消息都推进游标(顺序语义)
		// 收录具名消息的整组完成时刻(msgCursor),供 plan 解析 start_after 引用。
		if m.MessageID != "" {
			if msgids == nil {
				msgids = map[string]time.Time{}
			}
			msgids[m.MessageID] = msgCursor
		}
	}

	// 关闭:默认四次挥手;rst 表示对端(dst)单包中断连接。挥手接 msgCursor(最后一条消息末尾)。
	// UDP 无挥手。
	cursor = msgCursor
	if c.transport == TransportTCP {
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
	}
	return out, cursor, msgids, nil
}

// appendAt 把一个 stack 包包装成带时间戳的 PlannedPacket 追加到 out。
func appendAt(out []scenario.PlannedPacket, p scenario.Packet, t time.Time) []scenario.PlannedPacket {
	return append(out, scenario.PlannedPacket{Packet: p, Time: t})
}

// parseFlowStack 保留整栈模板并提取会话状态。不做字段级解构:各层 Fields 指针原样进模板,
// emit 时逐层浅拷贝并覆写派生量。层白名单/层序/必备层校验在 scenario.Validate(validateFlow);
// 这里只留展开必需的不变式:必须能定位会话传输层(tcp 或 udp)。
//
// transportIdx 全程使用 template 坐标系(关键):循环里每遇 tcp/udp 层就把 transportIdx
// 推进到该层入模板后的下标,循环结束直接对 template 内元素做类型校验——索引天然在界内,
// 不存在「stack 下标换算到 template 下标」的跨界运算,VXLAN 双 UDP 栈(outer + inner 会话)
// 也不会误取 outer(transportIdx 停在最后一个传输层,分段校验保证它就是紧邻会话层的那个)。
// 双会话层等非法输入在校验层由分段校验拦截;这里同样报错而非 panic,防御纵深。
func parseFlowStack(stack []scenario.Layer) (*conn, error) {
	c := &conn{transportIdx: -1}
	sessionSeen := false // 是否已见过会话层(任一种)
	want := ""           // 会话层要求的传输层名;空 = 无会话层(TCP 可省,走扫描分支)
	for _, l := range stack {
		if s, ok := l.Fields.(*scenario.TCPSessionFields); ok {
			if sessionSeen {
				return nil, fmt.Errorf("flow.stack 会话层(tcp_session 或 udp_session)不可同时出现")
			}
			sessionSeen = true
			c.session = session{open: s.Open, close: s.Close}
			c.transport = TransportTCP
			want = "tcp"
			continue
		}
		if _, ok := l.Fields.(*scenario.UDPSessionFields); ok {
			if sessionSeen {
				return nil, fmt.Errorf("flow.stack 会话层(tcp_session 或 udp_session)不可同时出现")
			}
			sessionSeen = true
			c.transport = TransportUDP
			want = "udp"
			continue
		}
		if l.Type == "tcp" || l.Type == "udp" {
			c.transportIdx = len(c.template) // template 坐标:最后一个传输层的下标
		}
		c.template = append(c.template, l)
	}
	switch {
	case want != "":
		// 分段校验保证传输层紧邻会话层,故最后一个传输层即会话传输层;
		// 类型不匹配报错而非 panic(防御纵深)。无传输层时 transportIdx 为 -1。
		if c.transportIdx < 0 || c.template[c.transportIdx].Type != want {
			return nil, fmt.Errorf("flow.stack 会话层(%s_session)前一层须为 %s 层", want, want)
		}
	case c.transportIdx == -1 || c.template[c.transportIdx].Type != "tcp":
		// 无会话层(仅 TCP 可省):最后一个传输层必须是 tcp。outer-only 的 vxlan 残栈
		// (只余 udp)在此拦截,不会把隧道外层 UDP 误当会话传输层。
		return nil, fmt.Errorf("flow.stack 需要 tcp 层(UDP 会话须显式声明 udp_session)")
	}
	if c.transport == TransportTCP && c.transportIdx >= 0 {
		if f, ok := c.template[c.transportIdx].Fields.(*scenario.TCPFields); ok {
			c.srcSeq, c.dstSeq = f.ClientISN, f.ServerISN
		}
	}
	c.profile = ProfileOf(stack)
	return c, nil
}

// emit 发一个方向的段:对模板逐层浅拷贝,覆写派生量(方向端点交换、传输层状态字段),
// 尾部追加 payload 字节。模板只被读取不回写;各层 Fields 指针跨包共享是安全的
// (builder 各 build* 只读字段,不改 *Fields;未写方向 VID 的 vlan 即共享同一指针)。
// 层数也可能随方向变化:写了方向化 VID 的 vlan 层在缺该向 VID 时整层摘除
// (上行带标签下行不带 / 上行双层下行单层),摘除只影响本次重建的 stack。
//
// 会话传输层(下标 == transportIdx)先按下标分派到 transportFields 覆写,再进 type
// switch——非会话传输层(如 VXLAN outer UDP)从结构上就走不到覆写逻辑,端口反转
// 不可能误伤 outer。
func (c *conn) emit(from side, flags []string, chunk []byte, summaryLayers []string) scenario.Packet {
	reverse := from == sideDst

	stack := make([]scenario.Layer, 0, len(c.template)+1)
	for i, l := range c.template {
		if i == c.transportIdx {
			stack = append(stack, scenario.Layer{Type: l.Type, Fields: c.transportFields(l, from, flags, chunk)})
			continue
		}
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

// transportFields 生成会话传输层(下标 == transportIdx)的展开字段:按 c.transport 分支。
// TCP 分支是 seq/ack/flags/MSS 覆写 + 端口交换(从旧 emit 头部原样搬入,TCP 产出不变);
// UDP 分支只做端口交换(端口是声明值,无派生字段)。
func (c *conn) transportFields(l scenario.Layer, from side, flags []string, chunk []byte) any {
	switch c.transport {
	case TransportUDP:
		udp := *l.Fields.(*scenario.UDPFields) // 浅拷贝
		if from == sideDst {
			udp.SPort, udp.DPort = udp.DPort, udp.SPort
		}
		return &udp
	default: // TransportTCP
		tcpF := l.Fields.(*scenario.TCPFields)
		tcp := *tcpF // 浅拷贝
		tcp.Seq, tcp.Ack = c.seqAck(from, flags, len(chunk))
		tcp.Flags = flags
		if hasFlag(flags, "SYN") && tcpF.MSS != nil {
			tcp.MSS = tcpF.MSS
		} else {
			tcp.MSS = nil // 非 SYN 包必须显式清掉(浅拷贝会把模板的 MSS 带过来)
		}
		if from == sideDst {
			tcp.SPort, tcp.DPort = tcp.DPort, tcp.SPort
		}
		return &tcp
	}
}

// seqAck 取当前方向的 seq/ack 并推进状态:seq 前进量 = payload 字节 + SYN(1) + FIN(1);
// 纯 ACK/RST 不前进。ack = 对端当前 seq。仅 TCP 会话调用。
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
	return slices.Contains(flags, f)
}

func sideOf(s string) side {
	if s == "dst" {
		return sideDst
	}
	return sideSrc
}
