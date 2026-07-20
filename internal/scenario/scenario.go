package scenario

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario 是一个场景文件的顶层结构。
type Scenario struct {
	LinkType string     `yaml:"link_type"`
	Seed     int64      `yaml:"seed"`
	BaseTime *AbsTime   `yaml:"base_time"` // 全局基准时刻(绝对 ISO8601);缺省=确定性 2020 基准(见 internal/plan)
	Packets  []Packet   `yaml:"packets"`
	Flows    []FlowSpec `yaml:"flows"`
}

// FlowSpec 是一条有状态会话;展开器把它降解成一串 Packet(见 internal/flow)。
// flow.stack 中的 src 表示 TCP SYN 发起方,dst 表示 SYN 接收方。
type FlowSpec struct {
	Name       string    `yaml:"name"`
	OffsetTime *Offset   `yaml:"offset_time"` // 流锚 = base_time + offset_time;缺省=base(跨流独立、并发,不接续别的 flow)
	Stack      []Layer   `yaml:"stack"`
	Messages   []Message `yaml:"messages"`
}

// Message 是一条方向性的应用层消息;当前只支持一个 payload 生产层。
type Message struct {
	From    string   `yaml:"from"` // src | dst
	Stack   []Layer  `yaml:"stack"`
	Segment *Segment `yaml:"segment"`
	// OffsetTime 是本消息起始相对**上一条消息末尾**的时长偏移(第一条消息相对"握手完成后",
	// 无握手则 = 流锚 anchor)。接续语义(见 internal/flow.Expand):无 offset 紧接上一条末尾;
	// 带 offset = 上一条末尾 + offset。链式 delta,offset>=0 天然单调,无需夹紧——慢响应拖慢
	// 下一条请求(正常非流水线 HTTP)。用于多轮请求间的间隔。握手固定 DefaultStep 不参与定时,
	// 故第一条消息的 offset 从握手结束算起,避免小 offset 与握手包撞时间。
	OffsetTime *Offset `yaml:"offset_time"`
}

// Segment 是消息的分段策略。MSS 为实际切段大小(0=不切,整条一段)。
type Segment struct {
	MSS int `yaml:"mss"`
	// Interval 是同一消息各数据段之间的时间间隔;缺省=1ms(与未显式定时的历史行为逐字节等价)。
	// 显式给出(如 +10ms)用于模拟慢速分段/RTT。只作用于数据段;对端 ACK 用 DefaultStep,
	// 不被数据段节奏传染(保持"只让数据慢"的语义纯净)。
	Interval *Offset `yaml:"interval"`
}

// Packet 是一个数据包:name 可选 + 由外到内的有序 layer 栈。
type Packet struct {
	Name          string   `yaml:"name"`
	OffsetTime    *Offset  `yaml:"offset_time"` // 该包时刻 = 上一包 + offset(第一包 = base_time+offset);缺省=接续默认游标(+1ms)
	Stack         []Layer  `yaml:"stack"`
	SummaryLayers []string `yaml:"-"` // flow 展开后保留应用层协议语义,仅用于 CLI 摘要
}

// PlannedPacket 是 scenario 模型 + 显式时间戳的中间态:
// standalone packets 与 flows 展开后的包在 internal/plan 汇流成 PlannedPacket 列表,
// 按 Time 排序后再交给 builder 序列化。内嵌 Packet 以复用 Name/Stack/SummaryLayers
// 与 quote_from 命名查找、摘要展示等既有逻辑。
type PlannedPacket struct {
	Packet
	Time time.Time
}

// Layer 是层栈中的一层:类型名 + 已按类型解码的字段结构(见各 *Fields)。
type Layer struct {
	Type   string
	Fields any
}

// Hex 接受十进制整数或 "0x88a8" 形式的十六进制字符串。
type Hex uint32

// UnmarshalYAML 允许 ethertype/tpid/type/checksum 等字段用 0x.. 或十进制书写。
func (h *Hex) UnmarshalYAML(node *yaml.Node) error {
	var i int64
	if err := node.Decode(&i); err == nil {
		*h = Hex(i)
		return nil
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return fmt.Errorf("非法十六进制 %q", s)
	}
	*h = Hex(v)
	return nil
}

// ParsePayloadHex 解析 0x 前缀的十六进制字符串。
func ParsePayloadHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, fmt.Errorf("payload_hex 需要 0x 前缀,例如 0xdeadbeef")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) == 0 {
		return nil, fmt.Errorf("payload_hex 不能为空")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("payload_hex 需要偶数个十六进制字符")
	}
	return hex.DecodeString(s)
}

// AbsTime 是绝对时刻(ISO8601),仅 base_time 使用:场景里唯一的绝对锚,
// offset_time 都相对它计算。写成形如 "+1s" 的偏移会在解析阶段失败。
type AbsTime struct {
	t time.Time
}

// UnmarshalYAML 把标量解析为 ISO8601 绝对时刻(UTC)。
func (a *AbsTime) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("base_time 需为字符串(ISO8601): %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("base_time 不能为空")
	}
	abs, err := parseAbsTime(s)
	if err != nil {
		return fmt.Errorf("非法绝对时刻 %q(如 2024-01-01T00:00:00Z): %w", s, err)
	}
	a.t = abs
	return nil
}

// Time 返回解析后的绝对时刻。
func (a *AbsTime) Time() time.Time { return a.t }

// Offset 是相对 base_time 的时长偏移,packet.offset_time / flow.offset_time /
// message.offset_time / segment.interval 使用。
// 仅接受非负时长(如 +1.5s / 500ms / 0s);负值与绝对时刻均在解析阶段失败——
// 负偏移通常意味着 base_time 选错了起点(应把 base_time 提前,而非用负 offset 够到零点之前)。
type Offset struct {
	d time.Duration
}

// UnmarshalYAML 把标量解析为时长偏移。
func (o *Offset) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("offset_time 需为字符串(时长偏移): %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("offset_time 不能为空")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("非法时长偏移 %q(如 +1.5s / 500ms / 0s): %w", s, err)
	}
	if d < 0 {
		return fmt.Errorf("时长偏移 %q 不能为负(若需早于 base_time,请把 base_time 提前)", s)
	}
	o.d = d
	return nil
}

// Duration 返回解析后的偏移时长。
func (o *Offset) Duration() time.Duration { return o.d }

// parseAbsTime 按 RFC3339Nano(及若干常见 layout)解析绝对时刻。
func parseAbsTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析为时间")
}

// 各层字段结构。指针字段表示"可选/是否显式给出"。
type (
	EthFields struct {
		Src       string `yaml:"src"`
		Dst       string `yaml:"dst"`
		EtherType *Hex   `yaml:"ethertype"`
	}
	VLANFields struct {
		VID  uint16 `yaml:"vid"`
		TPID *Hex   `yaml:"tpid"` // 后一个 VLAN 标签的 TPID(next==vlan 时映射到 Dot1Q.Type)
		Type *Hex   `yaml:"type"` // 显式覆盖 next-proto(制造断链)
	}
	IPv4Fields struct {
		Src      string  `yaml:"src"`
		Dst      string  `yaml:"dst"`
		TTL      *uint8  `yaml:"ttl"`
		Protocol *string `yaml:"protocol"` // 覆盖:tcp/udp/gre/ipv4
		// 畸形开关:当前解析但构建时忽略并告警。
		Checksum   *Hex  `yaml:"checksum"`
		FixLengths *bool `yaml:"fix_lengths"`
	}
	IPv6Fields struct {
		Src          string  `yaml:"src"`
		Dst          string  `yaml:"dst"`
		HopLimit     *uint8  `yaml:"hop_limit"` // 跳数限制(类比 IPv4 ttl),缺省 64
		TrafficClass *uint8  `yaml:"traffic_class"`
		FlowLabel    *uint32 `yaml:"flow_label"`
		NextHeader   *string `yaml:"next_header"` // 覆盖:tcp/udp/icmpv6/ipv4/ipv6(制造断链)
	}
	GREFields struct{}
	TCPFields struct {
		SPort     uint16   `yaml:"sport"`
		DPort     uint16   `yaml:"dport"`
		Flags     []string `yaml:"flags"`
		Seq       *uint32  `yaml:"seq"`
		Ack       *uint32  `yaml:"ack"`
		ClientISN uint32   `yaml:"client_isn"`
		ServerISN uint32   `yaml:"server_isn"`
		MSS       *uint16  `yaml:"mss"`      // SYN 通告 option(展开器仅在 SYN 上设)
		Checksum  *Hex     `yaml:"checksum"` // 解析但忽略
	}
	TCPSessionFields struct {
		Open  string `yaml:"open"`  // handshake(默认)| none
		Close string `yaml:"close"` // fin(默认)| rst | none
	}
	UDPFields struct {
		SPort uint16 `yaml:"sport"`
		DPort uint16 `yaml:"dport"`
	}
	ICMPFields struct {
		Type       yaml.Node `yaml:"type"`
		Code       yaml.Node `yaml:"code"`
		ID         *Hex      `yaml:"id"`
		Seq        uint16    `yaml:"seq"`
		Payload    string    `yaml:"payload"`
		PayloadHex string    `yaml:"payload_hex"`
		Quote      *Packet   `yaml:"quote"`
		QuoteFrom  string    `yaml:"quote_from"`
		Checksum   *Hex      `yaml:"checksum"` // 解析但忽略
		// 类型相关字段(RFC 792),映射到 ICMPv4 头 bytes 4-7(Id/Seq 位):
		Gateway *string `yaml:"gateway"` // 仅 redirect(type 5):网关 IPv4(bytes 4-7)
		Pointer *uint8  `yaml:"pointer"` // 仅 parameter_problem(type 12):出错字节偏移(byte 4)
		MTU     *uint16 `yaml:"mtu"`     // 仅 dest_unreachable(type 3) code 4:下一跳 MTU(bytes 6-7,RFC 1191)
	}
	// ICMPv6Fields 镜像 ICMPFields;校验和依赖 IPv6 伪首部(见 builder)。
	ICMPv6Fields struct {
		Type       yaml.Node `yaml:"type"`
		Code       yaml.Node `yaml:"code"`
		ID         *Hex      `yaml:"id"`
		Seq        uint16    `yaml:"seq"`
		Payload    string    `yaml:"payload"`
		PayloadHex string    `yaml:"payload_hex"`
		Quote      *Packet   `yaml:"quote"`
		QuoteFrom  string    `yaml:"quote_from"`
		Checksum   *Hex      `yaml:"checksum"` // 解析但忽略
		// 类型相关 4 字节字段(RFC 4443 §3):仅错误报文使用,echo 不用。
		MTU     *uint32 `yaml:"mtu"`     // 仅 packet_too_big(type 2):下一跳 MTU
		Pointer *uint32 `yaml:"pointer"` // 仅 parameter_problem(type 4):出错字节偏移
	}
	PayloadFields struct {
		Payload    string `yaml:"payload"`
		PayloadHex string `yaml:"payload_hex"`
	}
	// PayloadHex 对应 `- payload_hex: "0xdeadbeef"`(值是标量,非 map)。
	PayloadHex string

	DNSFields struct {
		ID                 uint16              `yaml:"id"`
		QR                 string              `yaml:"qr"`
		Opcode             string              `yaml:"opcode"`
		RCode              string              `yaml:"rcode"`
		Authoritative      bool                `yaml:"authoritative"`
		Truncated          bool                `yaml:"truncated"`
		RecursionDesired   bool                `yaml:"recursion_desired"`
		RecursionAvailable bool                `yaml:"recursion_available"`
		AuthenticatedData  bool                `yaml:"authenticated_data"`
		CheckingDisabled   bool                `yaml:"checking_disabled"`
		Questions          []DNSQuestionFields `yaml:"questions"`
		Answers            []DNSRRFields       `yaml:"answers"`
		Authorities        []DNSRRFields       `yaml:"authorities"`
		Additionals        []DNSRRFields       `yaml:"additionals"`
	}
	DNSQuestionFields struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Class string `yaml:"class"`
	}
	DNSRRFields struct {
		Name       string    `yaml:"name"`
		Type       string    `yaml:"type"`
		Class      string    `yaml:"class"`
		TTL        uint32    `yaml:"ttl"`
		Data       yaml.Node `yaml:"data"`
		PayloadHex string    `yaml:"payload_hex"` // 预留:畸形/未知 RDATA 后续实现
	}

	HTTPReqFields struct {
		Method  string            `yaml:"method"`
		Url     string            `yaml:"url"`
		Version string            `yaml:"version"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	}
	HTTPRespFields struct {
		Version string            `yaml:"version"`
		Status  int               `yaml:"status"`
		Reason  string            `yaml:"reason"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	}
)

// UnmarshalYAML 把单键 map(`- eth: {...}`)读成 {Type, Fields},保序由外层 list 保证。
func (l *Layer) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
		return fmt.Errorf("stack 元素必须是单键 map(如 `- eth: {...}`),见第 %d 行", node.Line)
	}
	l.Type = node.Content[0].Value
	val := node.Content[1]

	fields, err := decodeFields(l.Type, val)
	if err != nil {
		return fmt.Errorf("%s(第 %d 行): %w", l.Type, node.Line, err)
	}
	l.Fields = fields
	return nil
}

func decodeFields(typ string, val *yaml.Node) (any, error) {
	switch typ {
	case "eth":
		var f EthFields
		return &f, val.Decode(&f)
	case "vlan":
		var f VLANFields
		return &f, val.Decode(&f)
	case "ipv4":
		var f IPv4Fields
		return &f, val.Decode(&f)
	case "ipv6":
		var f IPv6Fields
		return &f, val.Decode(&f)
	case "gre":
		var f GREFields
		return &f, val.Decode(&f)
	case "tcp":
		var f TCPFields
		return &f, val.Decode(&f)
	case "tcp_session":
		var f TCPSessionFields
		return &f, val.Decode(&f)
	case "udp":
		var f UDPFields
		return &f, val.Decode(&f)
	case "icmp":
		var f ICMPFields
		return &f, val.Decode(&f)
	case "icmpv6", "icmp6":
		var f ICMPv6Fields
		return &f, val.Decode(&f)
	case "payload":
		var f PayloadFields
		return &f, val.Decode(&f)
	case "payload_hex":
		var s string
		if err := val.Decode(&s); err != nil {
			return nil, err
		}
		return PayloadHex(s), nil
	case "dns":
		var f DNSFields
		return &f, val.Decode(&f)
	case "http_request":
		var f HTTPReqFields
		return &f, val.Decode(&f)
	case "http_response":
		var f HTTPRespFields
		return &f, val.Decode(&f)
	default:
		return nil, fmt.Errorf("未知层类型 %q", typ)
	}
}

// Load 读取并解析场景文件,并为缺省 link_type 设置 ethernet。
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
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
	return nil
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
	for j, m := range f.Messages {
		if m.From != "src" && m.From != "dst" {
			return fmt.Errorf("messages[%d].from 只能是 src/dst,得到 %q", j, m.From)
		}
		if len(m.Stack) != 1 {
			return fmt.Errorf("messages[%d].stack 当前需恰好一个 payload 生产层,得到 %d 个", j, len(m.Stack))
		}
		switch m.Stack[0].Fields.(type) {
		case *HTTPReqFields, *HTTPRespFields, *PayloadFields, PayloadHex:
		default:
			return fmt.Errorf("messages[%d].stack[0] 不支持 %q", j, m.Stack[0].Type)
		}
		// segment.interval 只在切段(mss>0)时才有意义:不设 mss 时整条不切,interval 无处生效,
		// 静默吞掉会让用户误以为段间隔已生效。此处尽早报错。
		if m.Segment != nil && m.Segment.Interval != nil && m.Segment.MSS <= 0 {
			return fmt.Errorf("messages[%d].segment.interval 需配合 mss>0 才能切段(当前未设 mss,interval 不会生效)", j)
		}
	}
	return nil
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
