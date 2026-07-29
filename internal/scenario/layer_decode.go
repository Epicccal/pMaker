package scenario

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
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
	if t.Kind() == reflect.Pointer {
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
	case "telnet":
		var f TelnetFields
		return &f, decodeKnownFields(val, typ, &f)
	default:
		return nil, fmt.Errorf("未知层类型 %q", typ)
	}
}
