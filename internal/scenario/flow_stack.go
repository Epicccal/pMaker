package scenario

import (
	"fmt"
	"slices"
)

// flow.stack 分段校验:层白名单、层序、重复、必备层、派生量拒写,一张 rank 表承载。
// 无 vxlan 的单段 flow 是主路径,报错前缀仍是 stack.*(与历史文案逐字一致);
// 带 vxlan 时按 vxlan 下标切成 outer(underlay)/inner(overlay)两段,逐段校验。

// flowLayerRank 是 flow.stack 允许的层及其段内次序。表既是白名单(不在表里=拒),
// 也是顺序判据(rank 非递减);只有 vlan 允许同 rank 重复(QinQ)。
var flowLayerRank = map[string]int{
	"eth": 0, "vlan": 1, "ipv4": 2, "ipv6": 2, "udp": 3, "tcp": 3,
	"tcp_session": 4, "udp_session": 4,
}

// rankGroup 给「rank 相同但层类型不同」的冲突配准确文案:ipv4+ipv6 是网络层二选一、
// udp+tcp 是传输层二选一、tcp_session+udp_session 是会话层二选一,
// 不是「同一层重复」。
var rankGroup = map[int]string{
	2: "网络层(ipv4 或 ipv6)",
	3: "传输层(udp 或 tcp)",
	4: "会话层(tcp_session 或 udp_session)",
}

// segKind 是段身份,决定报错前缀与必备/禁用层。无 vxlan 的单段 flow 是主路径
// (全部既有示例),前缀不能是隧道口吻的 outer/inner。
type segKind int

const (
	segSingle segKind = iota // 无 vxlan 的普通 flow
	segOuter                 // vxlan 之前的 underlay 段
	segInner                 // vxlan 之后的 overlay 段
)

func (k segKind) label() string {
	switch k {
	case segOuter:
		return "stack.outer"
	case segInner:
		return "stack.inner"
	}
	return "stack"
}

// validateFlowSegment 校验一个隧道段:层白名单、层序、重复、必备层、派生量拒写。
func validateFlowSegment(seg []Layer, k segKind) error {
	p := k.label()
	prev, prevType, seen := -1, "", map[string]bool{}
	for _, l := range seg {
		r, ok := flowLayerRank[l.Type]
		if !ok {
			return fmt.Errorf("%s.%s: flow.stack 不支持该层(可用 eth/vlan/ipv4/ipv6/udp/vxlan/tcp/tcp_session/udp_session);请用 standalone packets", p, l.Type)
		}
		if r < prev {
			return fmt.Errorf("%s.%s: 层序须为 eth → vlan* → ipv4|ipv6 → udp|tcp → tcp_session|udp_session(展开器按声明序成帧,乱序产出的包无法解析)", p, l.Type)
		}
		if r == prev && l.Type != "vlan" {
			if l.Type == prevType {
				return fmt.Errorf("%s.%s: 该层在同一段内只能出现一次(仅 vlan 可重复)", p, l.Type)
			}
			return fmt.Errorf("%s: %s不可同时出现(请二选一),得到 %s 与 %s", p, rankGroup[r], prevType, l.Type)
		}
		switch f := l.Fields.(type) {
		case *TCPFields:
			if err := rejectDerivedTCP(f); err != nil {
				return fmt.Errorf("%s.tcp: %w", p, err)
			}
		case *UDPFields:
			// 端口是裸 uint16,漏写与显式 0 不可区分;outer dport 承载隧道身份,零值无语义
			// (RFC 7348 标准端口 4789)。畸形隧道走 standalone packets。
			if k == segOuter && f.DPort == 0 {
				return fmt.Errorf("%s.udp: dport 须非零(VXLAN 标准端口 4789);畸形隧道请用 standalone packets", p)
			}
		case *TCPSessionFields:
			// tcp_session 的 open/close 值校验
			if f.Open != "" && f.Open != "handshake" && f.Open != "none" {
				return fmt.Errorf("tcp_session.open 只能是 handshake/none,得到 %q", f.Open)
			}
			if f.Close != "" && f.Close != "fin" && f.Close != "rst" && f.Close != "none" {
				return fmt.Errorf("tcp_session.close 只能是 fin/rst/none,得到 %q", f.Close)
			}
		case *UDPSessionFields:
			// UDP Session 当前无字段需要校验
		}
		prev, prevType = r, l.Type
		seen[l.Type] = true
	}
	// 段级检查:必备层、传输层与会话层匹配、会话层不得出现在 outer 段。
	// 必备传输层按会话层决定:有 udp_session 需 udp,否则需 tcp(outer 段固定 udp)。
	need := "tcp"
	if k == segOuter {
		// vxlan 跑在 udp 上, 外层必须要有 UDP层
		need = "udp"
	} else if seen["udp_session"] {
		need = "udp"
	}
	switch {
	case !seen["eth"]:
		return fmt.Errorf("%s 需要 eth 层", p)
	case !seen["ipv4"] && !seen["ipv6"]:
		return fmt.Errorf("%s 需要网络层(ipv4 或 ipv6)", p)
	case k != segOuter && seen["tcp_session"] && seen["udp"]:
		return fmt.Errorf("%s.tcp_session: 会话层与传输层不匹配(tcp_session 需配 tcp,当前为 udp)", p)
	case k != segOuter && seen["udp_session"] && seen["tcp"]:
		return fmt.Errorf("%s.udp_session: 会话层与传输层不匹配(udp_session 需配 udp,当前为 tcp)", p)
	case k != segOuter && seen["udp"] && !seen["udp_session"]:
		// 「含 udp 无 tcp 且无会话层」是 UDP 用户最易犯的错,须给出专门文案,
		// 不能落到误导性的「需要 tcp 层」。
		return fmt.Errorf("%s 含 udp 无 tcp:UDP 会话需显式声明 udp_session(与 tcp_session 不同,不可省略)", p)
	case !seen[need]:
		return fmt.Errorf("%s 需要 %s 层", p, need)
	case k == segOuter && seen["tcp_session"]:
		return fmt.Errorf("%s.tcp_session: 只能在 vxlan 之后的 inner 段(会话跑在隧道内层)", p)
	case k == segOuter && seen["udp_session"]:
		return fmt.Errorf("%s.udp_session: 只能在 vxlan 之后的 inner 段(会话跑在隧道内层)", p)
	}
	return nil
}

// flowIsUDP 判断一条 flow.stack 是否声明了 UDP 会话(含 udp_session 层)。
// 供校验与跨层适配(FTP 一致性、message.stack 白名单)按传输层分流;
// 完整的传输/会话匹配校验由 validateFlowSegment 承载,这里只做只读判别。
func flowIsUDP(stack []Layer) bool {
	for _, l := range stack {
		if _, ok := l.Fields.(*UDPSessionFields); ok {
			return true
		}
	}
	return false
}

// tcpStreamLayers 是 TCP 流式应用层正向清单,CheckUDPStreamAppLayer 据此告警。
// 正向命中才告警,不是反向排除:UDP 会话要承载更多数据报协议(TFTP、QUIC、RTP……),
// 正向清单下新数据报层默认放开无需登记;新增 TCP 流式层须登记进本表
// (漏登记只漏一条告警,不误伤)。dns / payload / payload_hex 不在表里:DNS 本就是
// 「一条消息一个数据报」(RFC 1035 §4.2.1),payload 系列是原始字节通道。
var tcpStreamLayers = []string{
	"http_request", "http_response",
	"ftp_request", "ftp_response",
	"telnet",
	"smtp_request", "smtp_response",
	"pop3_request", "pop3_response",
	"imap_request", "imap_response",
	"eml_data",
}

// CheckUDPStreamAppLayer 扫描 UDP 会话 message.stack 里的 TCP 流式协议层(软告警):
// 流式层的语义是「字节流的一段」,放进单个数据报无帧边界语义 —— 照常出包,
// 按 tcpStreamLayers 正向命中才告警,畸形用例可故意为之。
func CheckUDPStreamAppLayer(s *Scenario) []Diagnostic {
	if s == nil {
		return nil
	}
	var ws []Diagnostic
	for i, f := range s.Flows {
		if !flowIsUDP(f.Stack) {
			continue
		}
		for k, m := range f.Messages {
			for j, l := range m.Stack {
				if !slices.Contains(tcpStreamLayers, l.Type) {
					continue
				}
				ws = append(ws, warnf(CodeUDPStreamAppLayer, flowMessageStackPath(i, k, j),
					"flows[%d](%s).messages[%d].stack[%d].%s: %q 是 TCP 流式协议层,放进单个 UDP 数据报无帧边界语义(解析端无法还原消息);确属故意的畸形用例可忽略,数据报应用层请用 payload/payload_hex 落字节或 dns",
					i, flowLabel(f.Name, i), k, j, l.Type, l.Type))
			}
		}
	}
	return ws
}

// rejectDerivedTCP 拒绝在 flow.stack 的 tcp 层手写 seq/ack/flags。
// 这三个字段由展开器按连接状态逐包推导(握手、收发方向、挥手都靠它),
// 手写的值会被覆盖,写了也白写。想构造畸形值请用 standalone packets 逐包手拼。
// 注意:清单只增不减 —— 以后往 TCPFields 加新的状态相关字段时要同步加进来,
// 否则该字段会被静默忽略。
func rejectDerivedTCP(t *TCPFields) error {
	for _, x := range []struct {
		name string
		set  bool
	}{{"seq", t.Seq != nil}, {"ack", t.Ack != nil}, {"flags", len(t.Flags) > 0}} {
		if x.set {
			return fmt.Errorf("%s 由展开器按连接状态推导,不支持在 flow.stack 覆盖;请用 standalone packet 构造该畸形包", x.name)
		}
	}
	return nil
}

// flowSegments 按 vxlan 下标切段。0 个 → 单段;1 个 → outer/inner 两段;≥2 → 拒。
func flowSegments(stack []Layer) ([][]Layer, error) {
	var at []int
	for i, l := range stack {
		if l.Type == "vxlan" {
			at = append(at, i)
		}
	}
	switch len(at) {
	case 0:
		return [][]Layer{stack}, nil
	case 1:
		return [][]Layer{stack[:at[0]], stack[at[0]+1:]}, nil
	default:
		return nil, fmt.Errorf("stack.vxlan: 暂只支持一层 vxlan 隧道(多层嵌套请用 standalone packets)")
	}
}

// CheckFlowOverrideWarning 扫描 flow.stack 的 length/checksum 覆盖(软告警):
// 覆盖值每包同值而真值逐包变,几乎必不符 —— 笔误提醒,恒定值畸形用例可忽略。
// 唯一豁免:就近网络层为 IPv4 的 UDP checksum 写 0(RFC 768:0 表示不校验,
// 恒定合法;就近判定与 builder 的 netLayer 推进同构;IPv6 下 0 非法,照告警)。
func CheckFlowOverrideWarning(s *Scenario) []Diagnostic {
	if s == nil {
		return nil
	}
	var ws []Diagnostic
	for i, f := range s.Flows {
		// 记录最近见过的网络层是否 IPv4,随扫描逐层更新,供 UDP checksum=0 的豁免判定
		nearV4 := false
		for j, l := range f.Stack {
			var fields []string
			switch g := l.Fields.(type) {
			case *IPv4Fields:
				nearV4 = true
				if g.Length != nil {
					fields = append(fields, "total_length")
				}
				if g.IHL != nil {
					fields = append(fields, "header_length")
				}
				if g.Checksum != nil {
					fields = append(fields, "checksum")
				}
			case *IPv6Fields:
				nearV4 = false
				if g.PayloadLength != nil {
					fields = append(fields, "payload_length")
				}
			case *TCPFields:
				if g.DataOffset != nil {
					fields = append(fields, "header_length")
				}
				if g.Checksum != nil {
					fields = append(fields, "checksum")
				}
			case *UDPFields:
				if g.Length != nil {
					fields = append(fields, "total_length")
				}
				// RFC 768 规定 IPv4 下 UDP checksum 为 0 表示 "不校验"，不需要打告警，此处进行豁免判定。
				if g.Checksum != nil && !(nearV4 && *g.Checksum == 0) {
					fields = append(fields, "checksum")
				}
			}
			for _, name := range fields {
				ws = append(ws, warnf(CodeFlowOverrideStatic, fmt.Sprintf("%s.%s", flowStackPath(i, j), name),
					"flows[%d](%s).stack[%d].%s: 覆盖值在 flow 中每包同值,而该字段真值逐包变,除个别包外将不符;故意构造可忽略本告警",
					i, flowLabel(f.Name, i), j, name))
			}
		}
	}
	return ws
}
