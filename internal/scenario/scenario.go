package scenario

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scenario 是一个场景文件的顶层结构。
type Scenario struct {
	LinkType string      `yaml:"link_type"`
	Seed     int64       `yaml:"seed"`
	Packets  []Packet    `yaml:"packets"`
	Flows    []yaml.Node `yaml:"flows"` // 仅用于探测:flows 场景当前尚未实现
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
		SPort    uint16   `yaml:"sport"`
		DPort    uint16   `yaml:"dport"`
		Flags    []string `yaml:"flags"`
		Seq      *uint32  `yaml:"seq"`
		Ack      *uint32  `yaml:"ack"`
		Checksum *Hex     `yaml:"checksum"` // 解析但忽略
	}
	UDPFields struct {
		SPort uint16 `yaml:"sport"`
		DPort uint16 `yaml:"dport"`
	}
	PayloadFields struct {
		Text string `yaml:"text"`
		Hex  string `yaml:"hex"`
	}
	// RawHex 对应 `- raw_hex: "deadbeef"`(值是标量,非 map)。
	RawHex string

	HTTPReqFields struct {
		Method  string            `yaml:"method"`
		Target  string            `yaml:"target"`
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
	case "udp":
		var f UDPFields
		return &f, val.Decode(&f)
	case "payload":
		var f PayloadFields
		return &f, val.Decode(&f)
	case "raw_hex":
		var s string
		if err := val.Decode(&s); err != nil {
			return nil, err
		}
		return RawHex(s), nil
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
	if len(s.Flows) > 0 {
		return nil, fmt.Errorf("检测到 flows 场景(有状态会话),当前仅支持 packets/stack 模型;flows 尚未实现")
	}
	if s.LinkType == "" {
		s.LinkType = "ethernet"
	}
	return &s, nil
}

// Validate 做语义校验:非空、必填字段存在。
func Validate(s *Scenario) error {
	if len(s.Packets) == 0 {
		return fmt.Errorf("没有 packets 可生成")
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
	}
	return nil
}
