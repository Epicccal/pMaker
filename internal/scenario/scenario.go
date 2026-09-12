package scenario

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load 读取并解析场景文件,并为缺省 link_type 设置 ethernet。
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Parse(data, filepath.Dir(path))
	if err != nil {
		// 报错带上文件名,便于定位(与历史行为一致)。
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	return s, nil
}

// Parse 从 YAML 字节解析 Scenario,并为缺省 link_type 设置 ethernet。
// baseDir 用于 @file 占位符的相对路径解析,也是其唯一可读边界(CLI 传 scenario 文件所在目录,
// MCP server 传配置的工作目录):@file 的路径(含绝对路径)一律须落在 baseDir 之内,越界硬错。
// Load 即「读文件 → 调 Parse」。
func Parse(data []byte, baseDir string) (*Scenario, error) {
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
		return nil, err
	}
	if s.LinkType == "" {
		s.LinkType = "ethernet"
	}
	// @file(<path>) 占位符替换:YAML decode 之后扫描所有 string 字段,把文件内容拼进去。
	// 路径须落在 baseDir 内(相对路径以它为基准,绝对路径也不得越界);占位符可在任意内容
	// 字段(body/payload/header 值/ftp args …)里出现,文件可只占字段的一部分。详见 file_placeholder.go。
	if err := ExpandFilePlaceholders(&s, baseDir); err != nil {
		return nil, err
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
		// 跨层位置规则(vxlan 前 udp / 后 inner eth)须在 stack 级校验,
		// validateLayer 只见单层;与下方逐层校验并列。
		if err := validateVXLANPosition(p.Stack); err != nil {
			return fmt.Errorf("packet[%d].vxlan: %w", i, err)
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

// Warnings 返回场景的软告警(非硬错):不影响生成,只提示配置可能不自洽,
// 供 CLI 在生成后输出供用户复核。畸形用例可能故意不一致,故只告警不阻断。当前覆盖:
//
//  1. FTP 端口协商一致性(CheckFTPDataPortConsistency):PASV/PORT/EPSV/EPRT 协商出的
//     端点与数据连接 dst IP:port 不一致、协商地址与控制连接角色不匹配时告警。
//  2. MIME multipart 一致性(CheckMultipartConsistency):boundary 与父层 Content-Type
//     头不符 / 缺 Content-Type / part encoding 与 Content-Transfer-Encoding 头不符或缺失。
//  3. HTTP 编码一致性(CheckHTTPConsistency):CL+TE 冲突、TE/CE 头与编码列表不符或缺失、
//     多个 chunked 或 chunked 不在末位、1xx/204 带 body、304 在 auto_content_length 时等。
//  4. IMAP literal 计数一致性(CheckIMAPLiteralConsistency):literal.octets 显式值与
//     实际字节数不符(计数撒谎)。
//  5. flow 覆盖告警(CheckFlowOverrideWarning):flow.stack 的 length/checksum 覆盖值每包
//     同值而真值逐包变(几乎全不符);唯一豁免 VXLAN 外层 UDP 在 IPv4 underlay 下写 0。
func Warnings(s *Scenario) []string {
	var ws []string
	ws = append(ws, CheckFTPDataPortConsistency(s)...)
	ws = append(ws, CheckMultipartConsistency(s)...)
	ws = append(ws, CheckHTTPConsistency(s)...)
	ws = append(ws, CheckIMAPLiteralConsistency(s)...)
	ws = append(ws, CheckFlowOverrideWarning(s)...)
	return ws
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
	// 分段校验:无 vxlan 单段(前缀 stack.*),带 vxlan 切 outer/inner 两段
	// (白名单/层序/重复/必备层/派生量拒写由 flowLayerRank 一张表承载,见 flow_stack.go)。
	segs, err := flowSegments(f.Stack)
	if err != nil {
		return err
	}
	if len(segs) == 1 {
		if err := validateFlowSegment(segs[0], segSingle); err != nil {
			return err
		}
	} else {
		if err := validateFlowSegment(segs[0], segOuter); err != nil {
			return err
		}
		if err := validateFlowSegment(segs[1], segInner); err != nil {
			return err
		}
	}
	// 逐层字段校验(tcp_session 无字段级 case,已由 validateFlowSegment 承载其值校验)。
	for _, l := range f.Stack {
		if l.Type == "tcp_session" {
			continue
		}
		if err := validateFlowLayer(l); err != nil {
			return fmt.Errorf("stack.%s: %w", l.Type, err)
		}
	}
	seenMsgID := map[string]bool{}
	for j, m := range f.Messages {
		if m.From != "src" && m.From != "dst" {
			return fmt.Errorf("messages[%d].from 只能是 src/dst,得到 %q", j, m.From)
		}
		if len(m.Stack) == 0 {
			return fmt.Errorf("messages[%d].stack 需至少一个 payload 生产层", j)
		}
		// message.stack 仍只允许 payload 生产层(白名单语义):eth/ipv4/tcp 等由 flow.stack 提供,
		// message.stack 不混入非 payload 层。支持一个或多个 payload 生产层,按栈顺序拼接。
		// 白名单须与 builder.PayloadBytes(internal/builder/payload.go)的 switch 保持一致。
		for k, l := range m.Stack {
			if !isPayloadProducingLayer(l) {
				return fmt.Errorf("messages[%d].stack[%d] 不支持 %q(只允许 payload 生产层,非标内容走 payload/payload_hex)", j, k, l.Type)
			}
			// 逐层字段校验:与 standalone packet 的 validateLayer 等价。此前 message.stack
			// 恰好一层时也有白名单 type switch 校验,但跳过了 validateLayer 的字段级规则,
			// 故 payload 同时配 payload+payload_hex(互斥)、ftp_response code 越界、
			// telnet 二字节命令带 option 等无效配置会静默通过、推迟到 build 才报错。
			// 多层后同样需要在 Validate 阶段尽早拦截,报错带 messages[%d].stack[%d].<type> 定位。
			if err := validateLayer(l); err != nil {
				return fmt.Errorf("messages[%d].stack[%d].%s: %w", j, k, l.Type, err)
			}
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

// isPayloadProducingLayer 判断一层是否为合法的 payload 生产层:Type 与 Fields 的
// 类型映射必须一致,且 Fields 类型属于 payload 生产层集合。
//
// 仅判 Fields 类型会放过 Layer{Type: "eth", Fields: &PayloadFields{...}} 这种 Type 与
// Fields 不匹配的状态——YAML 解码(decodeFields 按 Type 构造对应 Fields)不会产出,
// 但 Layer 是导出类型,程序代码可直接构造。此时 builder 按 Fields 产 payload、describe
// 按 Type 显示"eth",产出的包与摘要不一致,且一致性校验(如 FTP)按 Fields 类型分派
// 也会错位。故同时校验 Type→Fields 映射,二者须一致才视为合法 payload 生产层。
//
// 白名单的 Fields 集合须与 builder.PayloadBytes(internal/builder/payload.go)的 switch
// 保持一致;Type 名须与 decodeFields(internal/scenario/layer_decode.go)的 case 一致。
func isPayloadProducingLayer(l Layer) bool {
	switch l.Fields.(type) {
	case *HTTPReqFields:
		return l.Type == "http_request"
	case *HTTPRespFields:
		return l.Type == "http_response"
	case *FTPRequestFields:
		return l.Type == "ftp_request"
	case *FTPResponseFields:
		return l.Type == "ftp_response"
	case *TelnetFields:
		return l.Type == "telnet"
	case *SMTPRequestFields:
		return l.Type == "smtp_request"
	case *SMTPResponseFields:
		return l.Type == "smtp_response"
	case *POP3RequestFields:
		return l.Type == "pop3_request"
	case *POP3ResponseFields:
		return l.Type == "pop3_response"
	case *IMAPRequestFields:
		return l.Type == "imap_request"
	case *IMAPResponseFields:
		return l.Type == "imap_response"
	case *EMLDataFields:
		return l.Type == "eml_data"
	case *PayloadFields:
		return l.Type == "payload"
	case PayloadHex:
		return l.Type == "payload_hex"
	default:
		return false
	}
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

// validateChecksumRange 见 checksum.go;validateLengthRange 见 length.go。

// validateLayer 校验 standalone packets / message.stack / quote.stack 里的单层
// (无方向语义);flow.stack 的层走 validateFlowLayer。
func validateLayer(l Layer) error { return validateLayerIn(l, false) }

// validateFlowLayer 校验 flow.stack 里的单层:与 validateLayer 同一套规则,
// 额外放行只在 flow 里有意义的方向化字段(当前:vlan.src_vid/dst_vid)。
func validateFlowLayer(l Layer) error { return validateLayerIn(l, true) }

// validateLayerIn 是两者的共同实现,inFlow 表示该层来自 flow.stack。
func validateLayerIn(l Layer, inFlow bool) error {
	switch f := l.Fields.(type) {
	case *EthFields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
		if err := validateLengthRange(f.EtherType, 16, "eth.ethertype"); err != nil {
			return err
		}
	case *VLANFields:
		if err := validateVLANFields(f, inFlow); err != nil {
			return err
		}
	case *VXLANFields:
		if err := validateVXLANFields(f); err != nil {
			return err
		}
	case *IPv4Fields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
		if err := validateChecksumRange(f.Checksum); err != nil {
			return err
		}
		if err := validateLengthRange(f.Length, 16, "ipv4.total_length"); err != nil {
			return err
		}
		if err := validateLengthRange(f.IHL, 4, "ipv4.header_length"); err != nil {
			return err
		}
	case *IPv6Fields:
		if f.Src == "" || f.Dst == "" {
			return fmt.Errorf("需要 src 与 dst")
		}
		if err := validateLengthRange(f.PayloadLength, 16, "ipv6.payload_length"); err != nil {
			return err
		}
	case *TCPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
		if err := validateChecksumRange(f.Checksum); err != nil {
			return err
		}
		if err := validateLengthRange(f.DataOffset, 4, "tcp.header_length"); err != nil {
			return err
		}
	case *UDPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
		if err := validateChecksumRange(f.Checksum); err != nil {
			return err
		}
		if err := validateLengthRange(f.Length, 16, "udp.total_length"); err != nil {
			return err
		}
	case *ICMPFields:
		if err := validateChecksumRange(f.Checksum); err != nil {
			return err
		}
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
		if err := validateChecksumRange(f.Checksum); err != nil {
			return err
		}
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
		if err := validateFTPCommand(f.Command); err != nil {
			return err
		}
	case *FTPResponseFields:
		if err := validateFTPResponseCode(f.Code); err != nil {
			return err
		}
		if f.Message != "" && len(f.Lines) > 0 {
			return fmt.Errorf("message 与 lines 只能配置一个")
		}
		if f.Message == "" && len(f.Lines) == 0 {
			return fmt.Errorf("需要 message 或 lines")
		}
	case *TelnetFields:
		if err := validateTelnetFields(f); err != nil {
			return err
		}
	case *SMTPRequestFields:
		if err := validateSMTPRequestFields(f); err != nil {
			return err
		}
	case *SMTPResponseFields:
		if err := validateSMTPResponseFields(f); err != nil {
			return err
		}
	case *POP3RequestFields:
		if err := validatePOP3RequestFields(f); err != nil {
			return err
		}
	case *POP3ResponseFields:
		if err := validatePOP3ResponseFields(f); err != nil {
			return err
		}
	case *IMAPRequestFields:
		if err := validateIMAPRequestFields(f); err != nil {
			return err
		}
	case *IMAPResponseFields:
		if err := validateIMAPResponseFields(f); err != nil {
			return err
		}
	case *EMLDataFields:
		if err := validateEMLDataFields(f); err != nil {
			return err
		}
	case *HTTPReqFields:
		if err := validateHTTPReqFields(f); err != nil {
			return err
		}
		if err := validateHTTPMultipart(f.Body, f.Multipart); err != nil {
			return err
		}
	case *HTTPRespFields:
		if err := validateHTTPRespFields(f); err != nil {
			return err
		}
		if err := validateHTTPMultipart(f.Body, f.Multipart); err != nil {
			return err
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
