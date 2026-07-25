package scenario

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load 读取并解析场景文件,并为缺省 link_type 设置 ethernet。
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	// 未知字段一律报错而非静默忽略(带行号+字段名)。两层保障:
	//   - 顶层 decoder 开 KnownFields(true):覆盖 Scenario 直系字段树(packets/flows/
	//     messages/segment 等)。
	//   - decodeKnownFields:各 layer 经 Layer.UnmarshalYAML 内的 node.Decode 解码,
	//     yaml.v3 会新建 decoder 且不继承 knownFields,故 layer 内子字段由它在解码前
	//     反射校验补上(见 decodeKnownFields)。
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	if s.LinkType == "" {
		s.LinkType = "ethernet"
	}
	return &s, nil
}

// Validate 做语义校验:非空、必填字段存在。
// 时间约束(absolute base_time / offset-only start)已内建进 AbsTime/Offset 类型
// (AbsTime 只解析 ISO8601,Offset 只解析时长),不在这里重复校验。
func Validate(s *Scenario) error {
	if len(s.Packets) == 0 && len(s.Flows) == 0 {
		return fmt.Errorf("没有 packets 或 flows 可生成")
	}
	packetNames := packetNameCounts(s.Packets)
	for i, p := range s.Packets {
		if len(p.Stack) == 0 {
			return fmt.Errorf("packet[%d] 的 stack 为空", i)
		}
		for _, l := range p.Stack {
			if err := validateLayer(l); err != nil {
				return fmt.Errorf("packet[%d].%s: %w", i, l.Type, err)
			}
			if err := validateQuoteFrom(l, packetNames); err != nil {
				return fmt.Errorf("packet[%d].%s: %w", i, l.Type, err)
			}
		}
	}
	for i, f := range s.Flows {
		if err := validateFlow(f); err != nil {
			return fmt.Errorf("flow[%d](%s): %w", i, f.Name, err)
		}
	}
	// flow 名唯一(start_after 按名引用 flow,重名会歧义)与 start_after 引用/循环校验
	// 需要所有 flow 的 message_id 集合,故放在 per-flow 循环之后。
	if err := validateFlowNames(s.Flows); err != nil {
		return err
	}
	if err := validateStartAfter(s.Flows); err != nil {
		return err
	}
	return nil
}

// Warnings 返回场景的软告警(非硬错):不影响生成,但提示配置可能不自洽,
// 供 CLI 在生成后输出供用户复核。当前覆盖 FTP 控制通道 227/PORT 协商端口与
// 数据连接 dst IP:port 的一致性检查(畸形用例可能故意不一致,故只告警不阻断)。
func Warnings(s *Scenario) []string {
	return CheckFTPDataPortConsistency(s)
}

func packetNameCounts(pkts []Packet) map[string]int {
	out := map[string]int{}
	for _, p := range pkts {
		if p.Name != "" {
			out[p.Name]++
		}
	}
	return out
}

func validateQuoteFrom(l Layer, packetNames map[string]int) error {
	var name string
	switch f := l.Fields.(type) {
	case *ICMPFields:
		name = f.QuoteFrom
	case *ICMPv6Fields:
		name = f.QuoteFrom
	default:
		return nil
	}
	if name == "" {
		return nil
	}
	count := packetNames[name]
	if count == 0 {
		return fmt.Errorf("quote_from 引用未知 packet %q", name)
	}
	if count > 1 {
		return fmt.Errorf("quote_from 引用的 packet %q 不唯一", name)
	}
	return nil
}

func validateFlow(f FlowSpec) error {
	seen := map[string]bool{}
	for _, l := range f.Stack {
		seen[l.Type] = true
		if l.Type != "tcp_session" {
			if err := validateLayer(l); err != nil {
				return fmt.Errorf("stack.%s: %w", l.Type, err)
			}
		}
		if s, ok := l.Fields.(*TCPSessionFields); ok {
			if s.Open != "" && s.Open != "handshake" && s.Open != "none" {
				return fmt.Errorf("tcp_session.open 只能是 handshake/none,得到 %q", s.Open)
			}
			if s.Close != "" && s.Close != "fin" && s.Close != "rst" && s.Close != "none" {
				return fmt.Errorf("tcp_session.close 只能是 fin/rst/none,得到 %q", s.Close)
			}
		}
	}
	for _, required := range []string{"eth", "ipv4", "tcp"} {
		if !seen[required] {
			return fmt.Errorf("stack 需要 %s 层", required)
		}
	}
	seenMsgID := map[string]bool{}
	for j, m := range f.Messages {
		if m.From != "src" && m.From != "dst" {
			return fmt.Errorf("messages[%d].from 只能是 src/dst,得到 %q", j, m.From)
		}
		if len(m.Stack) != 1 {
			return fmt.Errorf("messages[%d].stack 当前需恰好一个 payload 生产层,得到 %d 个", j, len(m.Stack))
		}
		switch m.Stack[0].Fields.(type) {
		case *HTTPReqFields, *HTTPRespFields, *FTPRequestFields, *FTPResponseFields, *PayloadFields, PayloadHex:
		default:
			return fmt.Errorf("messages[%d].stack[0] 不支持 %q", j, m.Stack[0].Type)
		}
		// message_id 供跨流 start_after 引用,同一 flow 内必须唯一(否则引用歧义)。
		if m.MessageID != "" {
			if seenMsgID[m.MessageID] {
				return fmt.Errorf("messages[%d].message_id %q 在同一 flow 内重复", j, m.MessageID)
			}
			seenMsgID[m.MessageID] = true
		}
		// segment.interval 只在切段(mss>0)时才有意义:不设 mss 时整条不切,interval 无处生效,
		// 静默吞掉会让用户误以为段间隔已生效。此处尽早报错。
		if m.Segment != nil && m.Segment.Interval != nil && m.Segment.MSS <= 0 {
			return fmt.Errorf("messages[%d].segment.interval 需配合 mss>0 才能切段(当前未设 mss,interval 不会生效)", j)
		}
	}
	return nil
}

// SplitStartAfter 把 start_after 引用拆成 (flow, msg):"flow名" → (flow, ""),
// "flow名.message_id" → (flow, msg)。按第一个 '.' 切分,故 message_id 本身可含 '.'。
// 格式非法(flow 名为空,或 '.' 在首/尾使两段有空)返回 ok=false。msg=="" 表示引用整流结束。
// Validate 与 plan 共用此解析。
func SplitStartAfter(s string) (flow, msg string, ok bool) {
	i := strings.Index(s, ".")
	if i < 0 {
		// 裸 flow 名:引用整流结束(挥手后)。空串非法。
		if s == "" {
			return "", "", false
		}
		return s, "", true
	}
	if i <= 0 || i == len(s)-1 { // '.' 在首 / 在尾 → 两段必有空
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// flowNameCounts 统计非空 flow 名出现次数,供唯一性校验(镜像 packetNameCounts)。
func flowNameCounts(flows []FlowSpec) map[string]int {
	out := map[string]int{}
	for _, f := range flows {
		if f.Name != "" {
			out[f.Name]++
		}
	}
	return out
}

// validateFlowNames 校验非空 flow 名唯一:start_after 按名引用 flow,重名会歧义。
func validateFlowNames(flows []FlowSpec) error {
	for name, count := range flowNameCounts(flows) {
		if count > 1 {
			return fmt.Errorf("flow 名 %q 不唯一(出现 %d 次,start_after 按名引用会歧义)", name, count)
		}
	}
	return nil
}

// validateStartAfter 校验所有 start_after 引用(flow 级与 message 级):格式合法、
// 引用的 flow 存在且唯一、引用的 message_id 存在于该 flow、不引用本 flow(message 级
// 禁止同流自引,flow 级自引即自环由循环检测兜底),且依赖关系无环。纯结构分析,不需要 Expand。
//
// 循环检测在**事件粒度**而非 flow 粒度上进行。节点是 flow 的"起点 / 终点"与每条
// 参与引用的 message(具名被引 或 带引用);边 X→Y 表示"X 依赖 Y(X 在 Y 之后发生)"。
// 这样同一 flow 的前段被别的 flow 引用、后段又依赖别的 flow 的**合法交错**(典型如
// FTP:控制通道的 150 触发数据通道、数据通道整流结束再触发控制通道的 226)不会被
// 误判为环——150 在 226 之前,事件链是有向无环的。
//
// 对比:flow 粒度把"control 依赖 data"与"data 依赖 control"压成两个整流节点的 2-环
// 而误拦。事件粒度下这两条边分别落在 control.226 ↔ data.flowEnd,与 control.150 ↔
// data.flowStart,中间隔着流内链 control.150 → ... → control.226,方向一致、不成环。
func validateStartAfter(flows []FlowSpec) error {
	// flow 名 → 其具名 message_id 集合(用于校验被引 message 存在)。
	msgIDs := map[string]map[string]bool{}
	nameCount := flowNameCounts(flows)
	for _, f := range flows {
		if f.Name == "" {
			continue
		}
		set := map[string]bool{}
		for _, m := range f.Messages {
			if m.MessageID != "" {
				set[m.MessageID] = true
			}
		}
		msgIDs[f.Name] = set
	}

	// 引用合法性校验(格式、被引 flow 存在且唯一、被引 message 存在)在独立于建图的
	// checkRef 中完成;依赖图与检环由 BuildStartAfterGraph + DetectCycle 负责。
	checkRef := func(owner, ref string) error {
		refFlow, refMsg, ok := SplitStartAfter(ref)
		if !ok {
			return fmt.Errorf("%s 的 start_after %q 格式应为 \"flow名\" 或 \"flow名.message_id\"", owner, ref)
		}
		count := nameCount[refFlow]
		if count == 0 {
			return fmt.Errorf("%s 的 start_after 引用未知 flow %q", owner, refFlow)
		}
		if count > 1 {
			return fmt.Errorf("%s 的 start_after 引用的 flow %q 不唯一", owner, refFlow)
		}
		if refMsg != "" && !msgIDs[refFlow][refMsg] {
			return fmt.Errorf("%s 的 start_after 引用 flow %q 中未知 message_id %q", owner, refFlow, refMsg)
		}
		return nil
	}

	for _, f := range flows {
		// flow 级 start_after。
		if f.StartAfter != "" {
			if err := checkRef(fmt.Sprintf("flow %q", f.Name), f.StartAfter); err != nil {
				return err
			}
		}
		// message 级 start_after:禁止同流自引(链式 msgCursor 已保证流内顺序,自引或循环无意义)。
		for j, m := range f.Messages {
			if m.StartAfter == "" {
				continue
			}
			refFlow, _, _ := SplitStartAfter(m.StartAfter)
			if err := checkRef(fmt.Sprintf("flow %q 的 message[%d]", f.Name, j), m.StartAfter); err != nil {
				return err
			}
			if f.Name != "" && refFlow == f.Name {
				return fmt.Errorf("flow %q 的 message[%d] 的 start_after 禁止引用本 flow(同流自引)", f.Name, j)
			}
		}
	}

	// 建事件依赖图(BuildStartAfterGraph 与 plan 算时阶段共用图逻辑,见 start_after_graph.go),
	// 再三色 DFS 检环。回边(指向当前栈中灰节点的边)即环。
	g := BuildStartAfterGraph(flows)
	if err := g.DetectCycle(); err != nil {
		return err
	}
	return nil
}

// flowIndexByName 返回具名 flow(名唯一,见 validateFlowNames)的声明序号;未命名/不存在返回 -1。
func flowIndexByName(flows []FlowSpec, name string) int {
	for i, f := range flows {
		if name != "" && f.Name == name {
			return i
		}
	}
	return -1
}

// indexOfInt 返回 v 在 slice 中首次出现的下标,不存在返回 -1。
func indexOfInt(slice []int, v int) int {
	for i, x := range slice {
		if x == v {
			return i
		}
	}
	return -1
}

func validateLayer(l Layer) error {
	switch f := l.Fields.(type) {
	case *EthFields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
	case *IPv4Fields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
	case *IPv6Fields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
	case *TCPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
	case *UDPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
	case *ICMPFields:
		payloadKinds := 0
		for _, present := range []bool{f.Payload != "", f.PayloadHex != "", f.Quote != nil, f.QuoteFrom != ""} {
			if present {
				payloadKinds++
			}
		}
		if payloadKinds > 1 {
			return fmt.Errorf("quote/quote_from/payload/payload_hex 只能配置一个")
		}
		if f.PayloadHex != "" {
			if _, err := ParsePayloadHex(f.PayloadHex); err != nil {
				return err
			}
		}
		if f.Quote != nil {
			if len(f.Quote.Stack) == 0 {
				return fmt.Errorf("quote.stack 不能为空")
			}
			for _, l := range f.Quote.Stack {
				if err := validateLayer(l); err != nil {
					return fmt.Errorf("quote.%s: %w", l.Type, err)
				}
			}
			if len(f.Quote.Stack) == 0 || f.Quote.Stack[0].Type != "ipv4" {
				return fmt.Errorf("quote.stack 目前必须以 ipv4 开头")
			}
		}
	case *ICMPv6Fields:
		payloadKinds := 0
		for _, present := range []bool{f.Payload != "", f.PayloadHex != "", f.Quote != nil, f.QuoteFrom != ""} {
			if present {
				payloadKinds++
			}
		}
		if payloadKinds > 1 {
			return fmt.Errorf("quote/quote_from/payload/payload_hex 只能配置一个")
		}
		if f.PayloadHex != "" {
			if _, err := ParsePayloadHex(f.PayloadHex); err != nil {
				return err
			}
		}
		if f.Quote != nil {
			if len(f.Quote.Stack) == 0 {
				return fmt.Errorf("quote.stack 不能为空")
			}
			for _, l := range f.Quote.Stack {
				if err := validateLayer(l); err != nil {
					return fmt.Errorf("quote.%s: %w", l.Type, err)
				}
			}
			if len(f.Quote.Stack) == 0 || f.Quote.Stack[0].Type != "ipv6" {
				return fmt.Errorf("quote.stack 目前必须以 ipv6 开头")
			}
		}
	case *PayloadFields:
		if f.Payload != "" && f.PayloadHex != "" {
			return fmt.Errorf("payload 和 payload_hex 只能配置一个")
		}
		if f.PayloadHex != "" {
			if _, err := ParsePayloadHex(f.PayloadHex); err != nil {
				return err
			}
		}
	case *FTPRequestFields:
		if f.Command == "" {
			return fmt.Errorf("需要 command")
		}
	case *FTPResponseFields:
		if f.Code == 0 {
			return fmt.Errorf("需要 code")
		}
		if f.Message != "" && len(f.Lines) > 0 {
			return fmt.Errorf("message 与 lines 只能配置一个")
		}
		if f.Message == "" && len(f.Lines) == 0 {
			return fmt.Errorf("需要 message 或 lines")
		}
	case PayloadHex:
		if _, err := ParsePayloadHex(string(f)); err != nil {
			return err
		}
	case *DNSFields:
		if len(f.Questions)+len(f.Answers)+len(f.Authorities)+len(f.Additionals) == 0 {
			return fmt.Errorf("需要至少一个 question 或资源记录")
		}
		for i, q := range f.Questions {
			if q.Name == "" {
				return fmt.Errorf("questions[%d] 需要 name", i)
			}
		}
		for sec, rrs := range map[string][]DNSRRFields{"answers": f.Answers, "authorities": f.Authorities, "additionals": f.Additionals} {
			for i, rr := range rrs {
				if rr.Name == "" {
					return fmt.Errorf("%s[%d] 需要 name", sec, i)
				}
				hasPH := rr.PayloadHex != ""
				if hasPH {
					if rr.Data.Kind != 0 {
						// payload_hex 与 data 互斥:前者直接落原始 RDATA,后者走结构化编码,
						// 二者并存只会让 build 时取哪个产生歧义。
						return fmt.Errorf("%s[%d] payload_hex 与 data 只能配置一个", sec, i)
					}
					if _, err := ParsePayloadHex(rr.PayloadHex); err != nil {
						return fmt.Errorf("%s[%d]: %w", sec, i, err)
					}
				} else if rr.Data.Kind == 0 {
					return fmt.Errorf("%s[%d] 需要 data 或 payload_hex", sec, i)
				}
			}
		}
	}
	return nil
}
