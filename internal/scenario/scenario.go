package scenario

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
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
	Name       string  `yaml:"name"`
	OffsetTime *Offset `yaml:"offset_time"` // 流锚 = base_time + offset_time;缺省=base(跨流独立、并发,不接续别的 flow)
	// StartAfter 可选,形如 "flow名"(该 flow 整流结束,挥手后)或 "flow名.message_id"
	// (该消息整组完成,msgCursor);置则本 flow 的锚 = 被引时刻 + offset_time(缺省 0 紧接),
	// 实现"一个 flow 在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发数据通道)。
	// 见 internal/plan 的多遍拓扑编排。
	StartAfter string    `yaml:"start_after"`
	Stack      []Layer   `yaml:"stack"`
	Messages   []Message `yaml:"messages"`
}

// Message 是一条方向性的应用层消息;当前只支持一个 payload 生产层。
type Message struct {
	From    string   `yaml:"from"` // src | dst
	Stack   []Layer  `yaml:"stack"`
	Segment *Segment `yaml:"segment"`
	// OffsetTime 是本消息起始相对上一条消息末尾的时长偏移:缺省紧接上一条末尾,
	// 带 offset 则 = 上一条末尾 + offset。第一条消息的"上一条"= 握手完成后
	// (无握手则 = 流锚 anchor)。用于多轮请求间的间隔。
	OffsetTime *Offset `yaml:"offset_time"`
	// MessageID 是本消息的可选标识;供其它 flow 的 start_after 引用本消息整组完成
	// 时刻(msgCursor)。同一 flow 内必须唯一;不设则不被引用。见 internal/plan。
	MessageID string `yaml:"message_id"`
	// StartAfter 可选,形如 "flow名"(该 flow 整流结束,挥手后)或 "flow名.message_id"
	// (该消息整组完成,msgCursor);置则本消息起点 = 被引时刻 + offset_time(缺省 0 紧接),
	// 实现"某条消息在另一个 flow / 另一个 flow 某消息完成后才开始"(如控制通道触发本流
	// 某条迟到请求)。禁止引用本 flow(同流自引);流内顺序由 message 链式游标保证。
	// 见 internal/plan 的多遍拓扑编排与 internal/flow 的 resolve 回调。
	StartAfter string `yaml:"start_after"`
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

// AbsTime 是绝对时刻,仅 base_time 使用:场景里唯一的绝对锚,各 offset_time 的参考点
// 最终都溯源到它。按 UTC 解析 ISO8601/RFC3339(如 2024-01-01T00:00:00Z),也兼容
// 2024-01-01、2024-01-01 00:00:00 等宽松写法;写成形如 "+1s" 的偏移会在解析阶段失败。
type AbsTime struct {
	t time.Time
}

// UnmarshalYAML 把标量解析为绝对时刻(按 UTC;见 parseAbsTime 支持的格式)。
func (a *AbsTime) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("base_time 需为字符串(如 2024-01-01T00:00:00Z): %w", err)
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

// Offset 是非负时长偏移:packet.offset_time(相对上一包)、flow.offset_time(相对 base_time)、
// message.offset_time(相对上一条消息末尾)、segment.interval(同消息各数据段间隔)使用——
// 参考点因字段而异(见各字段注释与 internal/plan / internal/flow)。
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
	// FTPRequestFields 是一条 FTP 控制连接命令:COMMAND[ arg]\r\n。
	// command 原样输出(不强制大写),以便构造小写/非标命令等畸形用例。
	FTPRequestFields struct {
		Command string `yaml:"command"`
		Args    string `yaml:"args"`
	}
	// FTPResponseFields 是一条 FTP 控制连接响应。
	// 单行:message -> "code message\r\n"。
	// 多行(续行):lines -> "code-line1\r\n…\rcode lastline\r\n",
	// 最后一行用空格前缀,其余用连字符前缀(RFC 959 §4.1.3)。
	FTPResponseFields struct {
		Code    int      `yaml:"code"`
		Message string   `yaml:"message"`
		Lines   []string `yaml:"lines"`
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

// decodeKnownFields 把一个 layer 的 MappingNode 解码进 out,并在解码前校验未知字段。
//
// yaml.v3 的 KnownFields 只对顶层 decoder 生效,而各 layer 经 Layer.UnmarshalYAML
// 内的 node.Decode 解码时会新建 decoder 且不继承 knownFields。本函数负责 layer 子树
// 的未知字段校验:反射读 out 的 yaml tag 收集合法字段名,对照 node 的键报未知字段。
// 标量/null/序列等非 MappingNode 直接交给 Decode。
func decodeKnownFields(val *yaml.Node, typ string, out interface{}) error {
	if val.Kind != yaml.MappingNode {
		return val.Decode(out)
	}
	allowed := yamlFieldNames(out)
	var unknown []string
	line := val.Line
	for i := 0; i+1 < len(val.Content); i += 2 {
		k := val.Content[i]
		if !allowed[k.Value] {
			unknown = append(unknown, k.Value)
			line = k.Line
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("层 %q 不支持字段 %q(第 %d 行)", typ, strings.Join(unknown, ", "), line)
	}
	return val.Decode(out)
}

// yamlFieldNames 反射收集结构体(或其指针)的 YAML 合法字段名:优先取 yaml tag 名
// (逗号前部分),无 tag 则用 Go 字段名。覆盖各 *Fields 结构体的直接字段。
func yamlFieldNames(out interface{}) map[string]bool {
	t := reflect.TypeOf(out)
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	allowed := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		if name != "-" {
			allowed[name] = true
		}
	}
	return allowed
}

func decodeFields(typ string, val *yaml.Node) (any, error) {
	switch typ {
	case "eth":
		var f EthFields
		return &f, decodeKnownFields(val, typ, &f)
	case "vlan":
		var f VLANFields
		return &f, decodeKnownFields(val, typ, &f)
	case "ipv4":
		var f IPv4Fields
		return &f, decodeKnownFields(val, typ, &f)
	case "ipv6":
		var f IPv6Fields
		return &f, decodeKnownFields(val, typ, &f)
	case "gre":
		var f GREFields
		return &f, decodeKnownFields(val, typ, &f)
	case "tcp":
		var f TCPFields
		return &f, decodeKnownFields(val, typ, &f)
	case "tcp_session":
		var f TCPSessionFields
		return &f, decodeKnownFields(val, typ, &f)
	case "udp":
		var f UDPFields
		return &f, decodeKnownFields(val, typ, &f)
	case "icmp":
		var f ICMPFields
		return &f, decodeKnownFields(val, typ, &f)
	case "icmpv6", "icmp6":
		var f ICMPv6Fields
		return &f, decodeKnownFields(val, typ, &f)
	case "payload":
		var f PayloadFields
		return &f, decodeKnownFields(val, typ, &f)
	case "payload_hex":
		var s string
		if err := val.Decode(&s); err != nil {
			return nil, err
		}
		return PayloadHex(s), nil
	case "dns":
		var f DNSFields
		return &f, decodeKnownFields(val, typ, &f)
	case "http_request":
		var f HTTPReqFields
		return &f, decodeKnownFields(val, typ, &f)
	case "http_response":
		var f HTTPRespFields
		return &f, decodeKnownFields(val, typ, &f)
	case "ftp_request":
		var f FTPRequestFields
		return &f, decodeKnownFields(val, typ, &f)
	case "ftp_response":
		var f FTPResponseFields
		return &f, decodeKnownFields(val, typ, &f)
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
