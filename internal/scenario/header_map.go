package scenario

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// HeaderEntry 是 HeaderMap 中的一个键值对。
type HeaderEntry struct {
	Key   string
	Value string
}

// HeaderMap 是保留插入顺序、允许重复 key 的有序键值集合。
// 用于 HTTP headers / EML headers / SMTP params:YAML 解码按原序收下所有键值对
// (含同 key 重复),序列化按原序输出,builder 不再排序。
// 零值可用(空 slice),nil 安全(Len=0、Range 不迭代)。
type HeaderMap []HeaderEntry

// Len 返回条目数(含重复 key),对齐内置 len(HeaderMap)。
func (h HeaderMap) Len() int { return len(h) }

// Get 返回最后一个匹配 key 的值(对齐 map「后写覆盖」直觉;重复 key 取最后声明值)。
// 匹配大小写不敏感:HTTP/SMTP header 名 RFC 层面大小写不敏感(RFC 7230 §3.2),
// 与既有 writeHeaders 的 strings.EqualFold(k, "Content-Length") 行为一致。
func (h HeaderMap) Get(key string) (string, bool) {
	var lastVal string
	var found bool
	for _, e := range h {
		if strings.EqualFold(e.Key, key) {
			lastVal = e.Value
			found = true
		}
	}
	return lastVal, found
}

// Has 报告是否存在匹配 key(大小写不敏感,复用 Get 语义)。
func (h HeaderMap) Has(key string) bool { _, ok := h.Get(key); return ok }

// Range 按原序遍历,替代 builder 里的 for k := range h + 排序。
// fn 中修改 HeaderMap 不影响本次遍历(slice 长度在 Range 入口已由 for-range 快照固定)。
func (h HeaderMap) Range(fn func(key, value string)) {
	for _, e := range h {
		fn(e.Key, e.Value)
	}
}

// UnmarshalYAML 按 YAML mapping 的 Content 顺序逐对收下键值对(含同 key 重复),
// 绕开 yaml.v3 decode 进 map 时的去重。非 mapping(标量/序列)报错。
// 空 mapping {} → 空 HeaderMap;缺省/显式 null(nil)→ 不调用本方法,HeaderMap 保持 nil。
func (h *HeaderMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("应为 mapping(如 headers: { K: V }),得到 %s(第 %d 行)", nodeKindName(node.Kind), node.Line)
	}
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("mapping 内容损坏(键值不成对),第 %d 行", node.Line)
	}
	out := make(HeaderMap, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i].Value
		var v string
		if err := node.Content[i+1].Decode(&v); err != nil {
			return fmt.Errorf("header %q 的值(第 %d 行): %w", k, node.Content[i+1].Line, err)
		}
		out = append(out, HeaderEntry{Key: k, Value: v})
	}
	*h = out
	return nil
}

// nodeKindName 返回 yaml.Node.Kind 的人类可读名,用于错误信息。
func nodeKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.ScalarNode:
		return "标量"
	case yaml.SequenceNode:
		return "序列"
	case yaml.MappingNode:
		return "mapping"
	case yaml.AliasNode:
		return "别名"
	case 0:
		return "空"
	default:
		return fmt.Sprintf("kind=%d", kind)
	}
}
