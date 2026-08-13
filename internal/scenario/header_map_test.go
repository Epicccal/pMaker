package scenario

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 本文件覆盖 HeaderMap 的有序键值集合语义:YAML 解码保序 + 重复 key 全收、
// Get 大小写不敏感取最后值、Range 原序遍历、nil/空安全。对齐 HTTP/EML/SMTP 四处字段
// (Headers/Params)从 map[string]string 迁移到 HeaderMap 后的行为。

func TestHeaderMap_UnmarshalYAML_PreservesOrderAndDuplicates(t *testing.T) {
	var got struct {
		Headers HeaderMap `yaml:"headers"`
	}
	in := "headers:\n  Received: from mx1\n  Received: from mx2\n  From: a@b\n"
	if err := yaml.Unmarshal([]byte(in), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := HeaderMap{
		{Key: "Received", Value: "from mx1"},
		{Key: "Received", Value: "from mx2"},
		{Key: "From", Value: "a@b"},
	}
	if got.Headers.Len() != len(want) {
		t.Fatalf("Len=%d,期望 %d", got.Headers.Len(), len(want))
	}
	for i, e := range want {
		if got.Headers[i] != e {
			t.Errorf("条目 %d = %v,期望 %v", i, got.Headers[i], e)
		}
	}
}

func TestHeaderMap_UnmarshalYAML_EmptyMapping(t *testing.T) {
	// 空 mapping {} → 非 nil 空 slice(UnmarshalYAML 被调用、产出空集合)
	var got struct {
		Headers HeaderMap `yaml:"headers"`
	}
	if err := yaml.Unmarshal([]byte("headers: {}\n"), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Headers.Len() != 0 {
		t.Errorf("空 mapping Len=%d,期望 0", got.Headers.Len())
	}
}

func TestHeaderMap_UnmarshalYAML_NullStaysNil(t *testing.T) {
	// 缺省/显式 null → UnmarshalYAML 不被调用,HeaderMap 保持 nil。
	var got struct {
		Headers HeaderMap `yaml:"headers"`
	}
	if err := yaml.Unmarshal([]byte("body: hi\n"), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Headers != nil {
		t.Errorf("缺省 headers 应为 nil,得到 %v", got.Headers)
	}
	if got.Headers.Len() != 0 {
		t.Errorf("nil Len=%d,期望 0", got.Headers.Len())
	}
}

func TestHeaderMap_UnmarshalYAML_NonMappingRejects(t *testing.T) {
	cases := []string{
		"headers: [a, b]\n", // 序列
		"headers: scalar\n", // 标量
	}
	for i, in := range cases {
		var got struct {
			Headers HeaderMap `yaml:"headers"`
		}
		if err := yaml.Unmarshal([]byte(in), &got); err == nil {
			t.Errorf("case %d %q 应报错", i, in)
		}
	}
}

func TestHeaderMap_Get_LastValueCaseInsensitive(t *testing.T) {
	h := HeaderMap{
		{Key: "X", Value: "1"},
		{Key: "x", Value: "2"}, // 重复 key(大小写变体)
	}
	if v, ok := h.Get("X"); !ok || v != "2" {
		t.Errorf("Get(\"X\")=%q(ok=%v),期望 \"2\"", v, ok)
	}
	if v, ok := h.Get("x"); !ok || v != "2" {
		t.Errorf("Get(\"x\")=%q(ok=%v),期望 \"2\"", v, ok)
	}
	if _, ok := h.Get("Y"); ok {
		t.Errorf("Get(\"Y\") 应未命中")
	}
}

func TestHeaderMap_Get_CaseInsensitive_AutoContentLength(t *testing.T) {
	// 对齐 writeHeaders 的 auto 替换:用户写小写 content-length: auto 时
	// Get("Content-Length") 必须命中,否则 auto 不被替换(隐蔽合规 bug)。
	h := HeaderMap{{Key: "content-length", Value: "auto"}}
	if v, ok := h.Get("Content-Length"); !ok || v != "auto" {
		t.Errorf("大小写不敏感 Get 未命中: got %q(ok=%v)", v, ok)
	}
}

func TestHeaderMap_Has(t *testing.T) {
	h := HeaderMap{{Key: "Set-Cookie", Value: "a=1"}, {Key: "Set-Cookie", Value: "b=2"}}
	if !h.Has("set-cookie") {
		t.Errorf("Has(\"set-cookie\") 应为 true")
	}
	if h.Has("missing") {
		t.Errorf("Has(\"missing\") 应为 false")
	}
}

func TestHeaderMap_Range_PreservesOrder(t *testing.T) {
	h := HeaderMap{
		{Key: "B", Value: "2"},
		{Key: "A", Value: "1"},
		{Key: "B", Value: "3"},
	}
	var got strings.Builder
	h.Range(func(k, v string) {
		got.WriteString(k + "=" + v + ";")
	})
	want := "B=2;A=1;B=3;"
	if got.String() != want {
		t.Errorf("Range 顺序 = %q,期望 %q", got.String(), want)
	}
}

func TestHeaderMap_NilSafe(t *testing.T) {
	var h HeaderMap
	if h.Len() != 0 {
		t.Errorf("nil Len=%d,期望 0", h.Len())
	}
	if _, ok := h.Get("X"); ok {
		t.Errorf("nil Get 应未命中")
	}
	if h.Has("X") {
		t.Errorf("nil Has 应为 false")
	}
	// nil Range 不 panic
	h.Range(func(k, v string) { t.Errorf("nil Range 不应迭代") })
}
