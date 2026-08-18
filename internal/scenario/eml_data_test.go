package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 eml_data.go 的字段组合校验（模式互斥、空内容拒绝），
// 对齐 smtp_command_test.go 的风格：结构化/原始模式、raw/raw_hex 互斥。
//
// eml_data 是协议无关的内容层，framing（dot-stuffing/终止符）已下沉到接入层，
// 故本文件不再含 dot_stuff/dot_terminate 枚举校验（字段已移除）。

// emlLayer 包装一个 eml_data 层，便于表驱动构造。
func emlLayer(f scenario.EMLDataFields) scenario.Layer {
	return scenario.Layer{Type: "eml_data", Fields: &f}
}

// emlBaseStack 是承载 eml_data 校验的最小合法 stack（eth/ipv4/tcp）。
func emlBaseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 25}},
		layer,
	}
}

// validateEML 跑 Validate 并返回 error（nil 表示通过）。
func validateEML(t *testing.T, f scenario.EMLDataFields) error {
	t.Helper()
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: emlBaseStack(emlLayer(f))}}}
	return scenario.Validate(s)
}

func TestValidateEMLData_StructuredOK(t *testing.T) {
	cases := []scenario.EMLDataFields{
		{Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}}, Body: "body\r\n"},
		{Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}}}, // 仅 headers（合规空体邮件）
	}
	for i, c := range cases {
		if err := validateEML(t, c); err != nil {
			t.Errorf("case %d 应通过，得到: %v", i, err)
		}
	}
}

func TestValidateEMLData_BodyOnlyRejects(t *testing.T) {
	// 仅 body 无 headers → 报错（RFC 5322 邮件必有头；构造无头畸形请用 raw）
	err := validateEML(t, scenario.EMLDataFields{Body: "just body\r\n"})
	if err == nil {
		t.Fatalf("仅 body 无 headers 应报错")
	}
	if !strings.Contains(err.Error(), "headers 非空") {
		t.Errorf("错误应提及 headers 非空，得到: %v", err)
	}
}

func TestValidateEMLData_RawOK(t *testing.T) {
	cases := []scenario.EMLDataFields{
		{Raw: "From: a\r\n\r\nbody\r\n.\r\n"},
		{RawHex: "0x466f6f"},
		{Raw: "x"},
	}
	for i, c := range cases {
		if err := validateEML(t, c); err != nil {
			t.Errorf("case %d 应通过，得到: %v", i, err)
		}
	}
}

func TestValidateEMLData_ModeMutex(t *testing.T) {
	// 结构化 + 原始同设报错
	err := validateEML(t, scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		Raw:     "raw bytes",
	})
	if err == nil {
		t.Fatalf("结构化+原始同设应报错")
	}
	if !strings.Contains(err.Error(), "互斥") {
		t.Errorf("错误应提及互斥，得到: %v", err)
	}
}

func TestValidateEMLData_EmptyRejects(t *testing.T) {
	// 全空报错
	err := validateEML(t, scenario.EMLDataFields{})
	if err == nil {
		t.Fatalf("全空应报错")
	}
	if !strings.Contains(err.Error(), "空 EML") && !strings.Contains(err.Error(), "需要") {
		t.Errorf("错误应提及空内容，得到: %v", err)
	}
}

func TestValidateEMLData_RawRawHexMutex(t *testing.T) {
	// raw + raw_hex 同设报错
	err := validateEML(t, scenario.EMLDataFields{
		Raw:    "x",
		RawHex: "0x41",
	})
	if err == nil {
		t.Fatalf("raw+raw_hex 同设应报错")
	}
	if !strings.Contains(err.Error(), "raw") {
		t.Errorf("错误应提及 raw，得到: %v", err)
	}
}

func TestValidateEMLData_BadRawHex(t *testing.T) {
	// raw_hex 非法十六进制报错
	err := validateEML(t, scenario.EMLDataFields{RawHex: "0xZZ"})
	if err == nil {
		t.Fatalf("非法 raw_hex 应报错")
	}
}

func TestValidateEMLData_DotFieldsRemoved(t *testing.T) {
	// dot_stuff / dot_terminate 字段已移除（framing 下沉到接入层）：
	// 通过 YAML 解析路径验证二者现在都被当作未知字段拒绝（decodeKnownFields）。
	cases := []struct {
		field string // 已移除的字段名，同时用作错误断言关键字与文件名片段
		frag  string // 该字段在 eml_data 下的 YAML 片段（缩进对齐 headers/body）
	}{
		{field: "dot_stuff", frag: `          dot_stuff: off`},
		{field: "dot_terminate", frag: `          dot_terminate: off`},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			path := writeScenario(t, "eml_removed_"+c.field+".yaml", `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:00:00:00:00:01", dst: "00:00:00:00:00:02" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1234, dport: 25 }
      - eml_data:
          headers: { From: "a@b" }
          body: "x"
`+c.frag+"\n")
			_, err := scenario.Load(path)
			if err == nil {
				t.Fatalf("%s 字段已移除，应作为未知字段报错", c.field)
			}
			if !strings.Contains(err.Error(), c.field) {
				t.Errorf("错误应提及 %s，得到: %v", c.field, err)
			}
		})
	}
}

func TestValidateEMLData_UnknownFieldRejects(t *testing.T) {
	// 通过 YAML 解析路径验证未知字段（decodeKnownFields）
	path := writeScenario(t, "eml_unknown.yaml", `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:00:00:00:00:01", dst: "00:00:00:00:00:02" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1234, dport: 25 }
      - eml_data:
          headers: { From: "a@b" }
          body: "x"
          bogus_field: true
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatalf("未知字段应报错")
	}
	if !strings.Contains(err.Error(), "bogus_field") {
		t.Errorf("错误应提及 bogus_field，得到: %v", err)
	}
}
