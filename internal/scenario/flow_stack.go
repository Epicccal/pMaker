package scenario

import "fmt"

// flow.stack 分段校验:层白名单、层序、重复、必备层、派生量拒写,一张 rank 表承载。
// 无 vxlan 的单段 flow 是主路径,报错前缀仍是 stack.*(与历史文案逐字一致);
// 带 vxlan 时按 vxlan 下标切成 outer(underlay)/inner(overlay)两段,逐段校验。

// flowLayerRank 是 flow.stack 允许的层及其段内次序。表既是白名单(不在表里=拒),
// 也是顺序判据(rank 非递减);只有 vlan 允许同 rank 重复(QinQ)。
var flowLayerRank = map[string]int{
	"eth": 0, "vlan": 1, "ipv4": 2, "ipv6": 2, "udp": 3, "tcp": 3, "tcp_session": 4,
}

// rankGroup 给「rank 相同但层类型不同」的冲突配准确文案:ipv4+ipv6 是网络层二选一,
// 不是「同一层重复」。
var rankGroup = map[int]string{2: "网络层(ipv4 或 ipv6)", 3: "传输层(udp 或 tcp)"}

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
			return fmt.Errorf("%s.%s: flow.stack 不支持该层(可用 eth/vlan/ipv4/ipv6/udp/vxlan/tcp/tcp_session);请用 standalone packets", p, l.Type)
		}
		if r < prev {
			return fmt.Errorf("%s.%s: 层序须为 eth → vlan* → ipv4|ipv6 → udp|tcp → tcp_session(展开器按声明序成帧,乱序产出的包无法解析)", p, l.Type)
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
			// tcp_session 的 open/close 值校验从 validateFlow 主循环搬来:validateLayer 对
			// tcp_session 无 case,不搬会整块蒸发。
			if f.Open != "" && f.Open != "handshake" && f.Open != "none" {
				return fmt.Errorf("tcp_session.open 只能是 handshake/none,得到 %q", f.Open)
			}
			if f.Close != "" && f.Close != "fin" && f.Close != "rst" && f.Close != "none" {
				return fmt.Errorf("tcp_session.close 只能是 fin/rst/none,得到 %q", f.Close)
			}
		}
		prev, prevType = r, l.Type
		seen[l.Type] = true
	}
	need := "tcp"
	if k == segOuter {
		need = "udp"
	}
	switch {
	case !seen["eth"]:
		return fmt.Errorf("%s 需要 eth 层", p)
	case !seen["ipv4"] && !seen["ipv6"]:
		return fmt.Errorf("%s 需要网络层(ipv4 或 ipv6)", p)
	case !seen[need]:
		return fmt.Errorf("%s 需要 %s 层", p, need)
	case k == segOuter && seen["tcp_session"]:
		return fmt.Errorf("%s.tcp_session: 只能在 vxlan 之后的 inner 段(会话跑在隧道内层)", p)
	}
	return nil
}

// rejectDerivedTCP 拒绝由展开器按连接状态推导的字段。清单只增不减:
// 新增的方向/状态相关字段要同步加进来,否则会静默丢弃。
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

// CheckFlowOverrideWarning 扫描 flow.stack 的 length/checksum 覆盖(软告警)。
// 覆盖值每包同值,而展开包载荷逐包变,真值几乎全不符 —— 笔误提醒,恒定值畸形用例可忽略。
// checksum 只豁免 VXLAN 外层 UDP 在 IPv4 underlay 下写 0(RFC 7348 §5 免校验);其余照告警。
func CheckFlowOverrideWarning(s *Scenario) []string {
	if s == nil {
		return nil
	}
	var ws []string
	for i, f := range s.Flows {
		outerV4 := flowUnderlayIPv4(f.Stack)
		for j, l := range f.Stack {
			var fields []string
			switch g := l.Fields.(type) {
			case *IPv4Fields:
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
				if g.Checksum != nil && !(outerV4 && *g.Checksum == 0) {
					fields = append(fields, "checksum")
				}
			}
			for _, name := range fields {
				ws = append(ws, fmt.Sprintf(
					"flows[%d](%s).stack[%d].%s: 覆盖值在 flow 中每包同值,而该字段真值逐包变,除个别包外将不符;故意构造可忽略本告警",
					i, flowLabel(f.Name, i), j, name))
			}
		}
	}
	return ws
}

// flowUnderlayIPv4 判断 flow.stack 的 underlay 网络层是否 IPv4(外层 UDP checksum=0 的
// 豁免判据)。按声明序扫,遇到第一个网络层即定;vxlan 之前必有网络层(分段校验保证),
// 故先到 vxlan 才返回 false 仅在非法栈出现,不影响合法路径。
func flowUnderlayIPv4(stack []Layer) bool {
	for _, l := range stack {
		switch l.Type {
		case "ipv4":
			return true
		case "ipv6":
			return false
		}
	}
	return false
}
