package scenario

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// CodingList 是 HTTP 的 content_encoding / transfer_encoding 编码列表。
// 表示「按列表顺序施加的编码栈」(RFC 9110 §8.4 / RFC 9112 §6.1):
// 列表 [A, B] 构造 B(A(body)),对应头文本应写 "A, B"。
//
// YAML 同时接受**标量**与**序列**两种写法(复用 HeaderMap.UnmarshalYAML 的
// ScalarNode/SequenceNode 双分支习语):
//
//	content_encoding: gzip             # 标量 -> ["GZIP"]
//	content_encoding: [deflate, gzip]  # 序列 -> ["DEFLATE","GZIP"]
//
// 元素在解码层即归一化为**大写规范形**(TrimSpace + ToUpper):RFC 编码名大小写不敏感
// (RFC 9110 §8.4),与项目既有习语一致(POP3/SMTP/FTP/Telnet 命令表均「统一大写存储、
// 匹配大小写不敏感」)。下游校验(逐元素枚举)、builder fold(switch)、头与列表比对
// 统一在大写形上操作,不再各处重复 ToUpper。CodingList 是纯内部值(不直接上 wire,
// wire 上的头文本是用户自由文本),归一无损。
//
// 空/缺省/null/`none` -> nil(= 不编码);`none` 归一后为 `NONE`,与 nil 等价处理
// (见 IsNone)。非标量/非序列(如 mapping)报错。
type CodingList []string

// 编码名规范形常量(CodingList 元素归一后的合法取值)。
const (
	CodingGzip       = "GZIP"
	CodingDeflate    = "DEFLATE"
	CodingDeflateRaw = "DEFLATE_RAW"
	CodingChunked    = "CHUNKED"
	CodingNone       = "NONE" // 显式 none,与 nil 等价
)

// IsNone 报告列表是否等价于「不编码」:nil/空 或 仅含 NONE。
func (c CodingList) IsNone() bool {
	if len(c) == 0 {
		return true
	}
	for _, x := range c {
		if x != CodingNone {
			return false
		}
	}
	return true
}

// Effective 返回去掉 NONE 元素后的有效编码列表(归一后的真实应用顺序)。
// NONE 是显式「不编码」占位,在 fold 时跳过。返回的 slice 指向原底层数组(只读使用)。
func (c CodingList) Effective() CodingList {
	out := make(CodingList, 0, len(c))
	for _, x := range c {
		if x != CodingNone {
			out = append(out, x)
		}
	}
	return out
}

// UnmarshalYAML 同时接受标量与序列两种写法,元素归一为大写规范形(TrimSpace + ToUpper)。
// 空/缺省/显式 null 不会调用本方法(CodingList 保持 nil);显式空序列 [] -> 空 CodingList。
// 非 scalar/sequence(如 mapping)报错。
func (c *CodingList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("coding 标量(第 %d 行): %w", node.Line, err)
		}
		name := normalizeCoding(s)
		if name == "" {
			return nil
		}
		*c = CodingList{name}
		return nil
	case yaml.SequenceNode:
		out := make(CodingList, 0, len(node.Content))
		for i, n := range node.Content {
			var s string
			if err := n.Decode(&s); err != nil {
				return fmt.Errorf("coding 序列[%d](第 %d 行): %w", i, n.Line, err)
			}
			name := normalizeCoding(s)
			if name == "" {
				continue // 跳过空元素(容忍序列里混入空串)
			}
			out = append(out, name)
		}
		*c = out
		return nil
	default:
		return fmt.Errorf("应为标量或序列(如 content_encoding: gzip 或 [deflate, gzip]),得到 %s(第 %d 行)",
			nodeKindName(node.Kind), node.Line)
	}
}

// normalizeCoding 把单个编码名归一化:TrimSpace + ToUpper。空串返回空串(跳过)。
func normalizeCoding(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
