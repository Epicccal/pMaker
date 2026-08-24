package scenario_test

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 CodingList 的标量/序列双分支解码与归一化(TrimSpace + ToUpper)。
// 解码层做一次归一,下游校验/builder/比对统一在大写规范形上操作。

func decodeCodingList(t *testing.T, yamlText string) scenario.CodingList {
	t.Helper()
	type wrapper struct {
		List scenario.CodingList `yaml:"list"`
	}
	var w wrapper
	if err := yaml.Unmarshal([]byte(yamlText), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return w.List
}

func mustFailCodingList(t *testing.T, yamlText string) {
	t.Helper()
	type wrapper struct {
		List scenario.CodingList `yaml:"list"`
	}
	var w wrapper
	if err := yaml.Unmarshal([]byte(yamlText), &w); err == nil {
		t.Fatalf("期望解码失败,实际成功: %v", w.List)
	}
}

func TestCodingList_Scalar(t *testing.T) {
	got := decodeCodingList(t, "list: gzip")
	want := scenario.CodingList{"GZIP"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("标量 gzip -> %v, want %v", got, want)
	}
}

func TestCodingList_ScalarNormalized(t *testing.T) {
	cases := map[string]scenario.CodingList{
		`list: gzip`:        {"GZIP"},
		`list: Gzip`:        {"GZIP"},
		`list: GZIP`:        {"GZIP"},
		`list: "  gzip "`:   {"GZIP"}, // 前后空白裁剪
		`list: Chunked`:     {"CHUNKED"},
		`list: deflate_raw`: {"DEFLATE_RAW"},
	}
	for in, want := range cases {
		got := decodeCodingList(t, in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q -> %v, want %v", in, got, want)
		}
	}
}

func TestCodingList_Sequence(t *testing.T) {
	got := decodeCodingList(t, "list: [deflate, gzip]")
	want := scenario.CodingList{"DEFLATE", "GZIP"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("序列 [deflate, gzip] -> %v, want %v", got, want)
	}
}

func TestCodingList_SequenceNormalized(t *testing.T) {
	got := decodeCodingList(t, "list: [deflate, gzip, chunked]")
	want := scenario.CodingList{"DEFLATE", "GZIP", "CHUNKED"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCodingList_Empty(t *testing.T) {
	// 空序列 / null / 缺省 / 标量 none / 空白 标量 -> nil 或空,均 IsNone。
	cases := []string{
		"list: []",
		"list: null",
		"list: \"\"",
		"list: none",
		"list: \"   \"",
		"list: [none]",
		"list: [none, none]",
	}
	for _, in := range cases {
		got := decodeCodingList(t, in)
		if !got.IsNone() {
			t.Errorf("%q -> %v, 期望 IsNone=true", in, got)
		}
	}
}

func TestCodingList_MappingRejected(t *testing.T) {
	// 非 scalar/sequence(如 mapping)报错。
	mustFailCodingList(t, "list: {a: b}")
}

func TestCodingList_EffectiveSkipsNone(t *testing.T) {
	c := scenario.CodingList{"NONE", "GZIP", "NONE", "CHUNKED"}
	got := c.Effective()
	want := scenario.CodingList{"GZIP", "CHUNKED"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Effective -> %v, want %v", got, want)
	}
}

func TestCodingList_IsNone(t *testing.T) {
	if !(scenario.CodingList(nil)).IsNone() {
		t.Error("nil 应 IsNone")
	}
	if !(scenario.CodingList{}).IsNone() {
		t.Error("空应 IsNone")
	}
	if !(scenario.CodingList{"NONE"}).IsNone() {
		t.Error("[NONE] 应 IsNone")
	}
	if (scenario.CodingList{"GZIP"}).IsNone() {
		t.Error("[GZIP] 不应 IsNone")
	}
	if (scenario.CodingList{"NONE", "GZIP"}).IsNone() {
		t.Error("[NONE, GZIP] 不应 IsNone(含真实编码)")
	}
}
