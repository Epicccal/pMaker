package scenario

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scenario 是一个场景文件的顶层结构。
type Scenario struct {
	LinkType string     `yaml:"link_type"`
	Seed     int64      `yaml:"seed"`
	Packets  []Packet   `yaml:"packets"`
	Flows    []FlowSpec `yaml:"flows"`
}

// FlowSpec 是一条有状态会话;展开器把它降解成一串 Packet(见 internal/flow)。
// flow.stack 中的 src 表示 TCP SYN 发起方,dst 表示 SYN 接收方。
type FlowSpec struct {
	Name     string    `yaml:"name"`
	Stack    []Layer   `yaml:"stack"`
	Messages []Message `yaml:"messages"`
}

// Message 是一条方向性的应用层消息;当前只支持一个 payload 生产层。
type Message struct {
	From    string   `yaml:"from"` // src | dst
	Stack   []Layer  `yaml:"stack"`
	Segment *Segment `yaml:"segment"`
}

// Segment 是消息的分段策略。MSS 为实际切段大小(0=不切,整条一段)。
type Segment struct {
	MSS int `yaml:"mss"`
}

// Packet 是一个数据包:name 可选 + 由外到内的有序 layer 栈。
type Packet struct {
	Name  string  `yaml:"name"`
	Stack []Layer `yaml:"stack"`
}

// Layer 是层栈中的一层:类型名 + 已按类型解码的字段结构(见各 *Fields)。
type Layer struct {
	Type   string
	Fields any
}

// Hex 接受十进制整数或 "0x88a8" 形式的十六进制字符串。
type Hex uint32

// UnmarshalYAML 允许 ethertype/tpid/type/checksum 用 0x.. 或十进制书写。
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
		// 畸形开关:最小版解析但忽略(build 时告警)。
		Checksum   *Hex  `yaml:"checksum"`
		FixLengths *bool `yaml:"fix_lengths"`
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
		Checksum   *Hex      `yaml:"checksum"` // 解析但忽略
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

// Load 读取并解析场景文件;顶层若是 flows 则明确报未实现。
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
func Validate(s *Scenario) error {
	if len(s.Packets) == 0 && len(s.Flows) == 0 {
		return fmt.Errorf("没有 packets 或 flows 可生成")
	}
	for i, p := range s.Packets {
		if len(p.Stack) == 0 {
			return fmt.Errorf("packet[%d] 的 stack 为空", i)
		}
		for _, l := range p.Stack {
			if err := validateLayer(l); err != nil {
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
	case *TCPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
	case *UDPFields:
		if f.SPort == 0 || f.DPort == 0 {
			return fmt.Errorf("需要 sport 与 dport")
		}
	case *ICMPFields:
		if f.Payload != "" && f.PayloadHex != "" {
			return fmt.Errorf("payload 和 payload_hex 只能配置一个")
		}
		if f.Quote != nil && (f.Payload != "" || f.PayloadHex != "") {
			return fmt.Errorf("quote 与 payload/payload_hex 只能配置一个")
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
				if rr.PayloadHex != "" {
					if _, err := ParsePayloadHex(rr.PayloadHex); err != nil {
						return fmt.Errorf("%s[%d]: %w", sec, i, err)
					}
				}
				if rr.PayloadHex == "" && rr.Data.Kind == 0 {
					return fmt.Errorf("%s[%d] 需要 data", sec, i)
				}
			}
		}
	}
	return nil
}
