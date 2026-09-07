package scenario

import (
	"fmt"
	"reflect"
	"sort"
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

// layerDecoder 把一个 layer 的 YAML 值节点解码成对应的 *Fields(或标量层的值类型)。
// typ 仅用于错误信息(未知字段报错要点名是哪个层)。
type layerDecoder func(val *yaml.Node, typ string) (any, error)

// fieldsDecoder 生成「解码进 T 并校验未知字段」的标准 decoder,覆盖绝大多数层。
// 与原 switch 分支逐字等价:即便 decodeKnownFields 报错也返回非 nil 的 *T
// (调用方 Layer.UnmarshalYAML 只在 err == nil 时用 Fields,此处保持原行为)。
func fieldsDecoder[T any]() layerDecoder {
	return func(val *yaml.Node, typ string) (any, error) {
		var f T
		return &f, decodeKnownFields(val, typ, &f)
	}
}

// layerDecoders 是**合法层名的单一真相源**:键 = YAML 里可写的层名,值 = 该层的解码器。
// 成员关系即「已知层」,LayerTypes() 直接由它派生,decodeFields 也只查它——
// 加层只在此一处登记,不存在「加了 case 忘了别处、层名有实现却无文档入口」的路径
// (与 imapCommands / ftpCommands 等单表同一套理由)。
//
// MCP 的 schema resource 覆盖性测试(cmd/pmaker-mcp)拿 LayerTypes() 与
// resources/schema/*.md 双向比对,故新增层必须同步加文档,否则测试红。
var layerDecoders = map[string]layerDecoder{
	// L2
	"eth":  fieldsDecoder[EthFields](),
	"vlan": fieldsDecoder[VLANFields](),
	// L3
	"ipv4":  fieldsDecoder[IPv4Fields](),
	"ipv6":  fieldsDecoder[IPv6Fields](),
	"gre":   fieldsDecoder[GREFields](),
	"vxlan": fieldsDecoder[VXLANFields](),
	// L4
	"tcp":         fieldsDecoder[TCPFields](),
	"tcp_session": fieldsDecoder[TCPSessionFields](),
	"udp":         fieldsDecoder[UDPFields](),
	// 控制
	"icmp":   fieldsDecoder[ICMPFields](),
	"icmpv6": fieldsDecoder[ICMPv6Fields](),
	"icmp6":  fieldsDecoder[ICMPv6Fields](), // icmpv6 的别名
	// 应用
	"dns":           fieldsDecoder[DNSFields](),
	"http_request":  fieldsDecoder[HTTPReqFields](),
	"http_response": fieldsDecoder[HTTPRespFields](),
	"ftp_request":   fieldsDecoder[FTPRequestFields](),
	"ftp_response":  fieldsDecoder[FTPResponseFields](),
	"telnet":        fieldsDecoder[TelnetFields](),
	"smtp_request":  fieldsDecoder[SMTPRequestFields](),
	"smtp_response": fieldsDecoder[SMTPResponseFields](),
	"pop3_request":  fieldsDecoder[POP3RequestFields](),
	"pop3_response": fieldsDecoder[POP3ResponseFields](),
	"imap_request":  fieldsDecoder[IMAPRequestFields](),
	"imap_response": fieldsDecoder[IMAPResponseFields](),
	"eml_data":      fieldsDecoder[EMLDataFields](),
	// 兜底
	"payload": fieldsDecoder[PayloadFields](),
	// payload_hex 是标量层(`- payload_hex: "0x..."`),值不是 map,故不走 fieldsDecoder。
	"payload_hex": func(val *yaml.Node, _ string) (any, error) {
		var s string
		if err := val.Decode(&s); err != nil {
			return nil, err
		}
		return PayloadHex(s), nil
	},
}

// LayerTypes 返回全部合法层名(字典序),派生自 layerDecoders 这一单一真相源。
// 供 MCP schema 文档覆盖性测试等「需要枚举全部层」的场景使用。
func LayerTypes() []string {
	names := make([]string, 0, len(layerDecoders))
	for name := range layerDecoders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func decodeFields(typ string, val *yaml.Node) (any, error) {
	dec, ok := layerDecoders[typ]
	if !ok {
		return nil, fmt.Errorf("未知层类型 %q", typ)
	}
	return dec(val, typ)
}
