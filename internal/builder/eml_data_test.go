package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 eml_data 应用层序列化：结构化/原始模式、dot-stuffing、终止符、头注入、
// 空头/空体边界，断言字节符合 RFC 5322 / RFC 5321 §4.5.2。走 PayloadBytes 与 serializeStack
// 同一序列化路径，确保行为一致。

func TestSerializeEMLData_Structured(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: map[string]string{
			"From":    "alice@example.com",
			"To":      "bob@example.net",
			"Subject": "Hello",
		},
		Body: "This is the email body.\r\nSecond line.\r\n",
	}
	// headers 按 key 字典序：From < Subject < To
	want := "From: alice@example.com\r\n" +
		"Subject: Hello\r\n" +
		"To: bob@example.net\r\n" +
		"\r\n" +
		"This is the email body.\r\n" +
		"Second line.\r\n" +
		".\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_Raw(t *testing.T) {
	f := &scenario.EMLDataFields{
		Raw:          "From: a\r\nTo: b\r\n\r\nbody\r\n.\r\n",
		DotStuff:     "off",
		DotTerminate: "off",
	}
	want := "From: a\r\nTo: b\r\n\r\nbody\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_RawHex(t *testing.T) {
	f := &scenario.EMLDataFields{
		RawHex:       "0x466f6f", // "Foo"
		DotTerminate: "off",
		DotStuff:     "off",
	}
	want := "Foo"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_DotStuff_On(t *testing.T) {
	// dot_stuff 缺省 auto=on：body 行首 . → ..
	f := &scenario.EMLDataFields{
		Body: ".hidden dot\r\nnormal line\r\n",
	}
	want := "\r\n..hidden dot\r\nnormal line\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_DotStuff_Off(t *testing.T) {
	// dot_stuff=off：body 行首 . 不变（畸形）
	f := &scenario.EMLDataFields{
		Body:     ".hidden dot\r\nnormal line\r\n",
		DotStuff: "off",
	}
	want := "\r\n.hidden dot\r\nnormal line\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_DotStuff_DotOnlyLine(t *testing.T) {
	// body 行只有 . → stuffing 产出 .. （非终止符）
	f := &scenario.EMLDataFields{
		Body:     ".\r\nafter\r\n",
		DotStuff: "on",
	}
	// 结构化模式：空 headers → "\r\n" + body；dot_stuff 后 "..\r\nafter\r\n"；终止符 .\r\n
	want := "\r\n..\r\nafter\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_DotTerminate_Off(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers:      map[string]string{"Subject": "no term"},
		Body:         "body\r\n",
		DotTerminate: "off",
	}
	want := "Subject: no term\r\n\r\nbody\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_HeaderInjection(t *testing.T) {
	// headers 值含 \r\n 裸透传不转义（头注入畸形）
	f := &scenario.EMLDataFields{
		Headers: map[string]string{
			"X-Custom": "value\r\nInjected: header",
		},
		Body:         "body\r\n",
		DotTerminate: "off",
		DotStuff:     "off",
	}
	want := "X-Custom: value\r\nInjected: header\r\n\r\nbody\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_HeadersEmpty_BodyOnly(t *testing.T) {
	// headers 为空 + body 非空 → 仍插空行（\r\n + body）
	f := &scenario.EMLDataFields{
		Body:         "just body\r\n",
		DotTerminate: "off",
		DotStuff:     "off",
	}
	want := "\r\njust body\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_BodyEmpty_HeadersOnly(t *testing.T) {
	// body 为空 + headers 非空 → headers + 空行（headers 末尾 \r\n 即空行）+ 终止符
	f := &scenario.EMLDataFields{
		Headers: map[string]string{"Subject": "empty body"},
	}
	// headers 输出 "Subject: empty body\r\n"，再插空行 "\r\n"，body 空，终止符 .\r\n
	want := "Subject: empty body\r\n\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_ConsecutiveBlankLines(t *testing.T) {
	// body 含连续空行 → dot-stuffing 不影响空行（行首非 .）
	f := &scenario.EMLDataFields{
		Body:     "line1\r\n\r\n\r\nline2\r\n",
		DotStuff: "on",
	}
	// 结构化：\r\n + body；dot-stuffing 不改空行；终止符 .\r\n
	want := "\r\nline1\r\n\r\n\r\nline2\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_RawEndsWithCRLF_TerminateOn(t *testing.T) {
	// raw 以 \r\n 结尾 + dot_terminate=on → 追加 .\r\n（去重，不双 \r\n）
	f := &scenario.EMLDataFields{
		Raw:      "From: a\r\n\r\nbody\r\n",
		DotStuff: "off",
	}
	want := "From: a\r\n\r\nbody\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeEMLData_RawNoCRLF_TerminateOn(t *testing.T) {
	// raw 不以 \r\n 结尾 + dot_terminate=on → 追加 \r\n.\r\n
	f := &scenario.EMLDataFields{
		Raw:      "raw bytes no crlf",
		DotStuff: "off",
	}
	want := "raw bytes no crlf\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestParseBackEMLData 构造一个最小 eth/ipv4/tcp + eml_data 包，回读断言 TCP payload
// 为结构化 EML 字节（含终止符），证明 eml_data 经 serializeStack 序列化为 gopacket.Payload。
func TestParseBackEMLData(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.25", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 25, Flags: []string{"PSH", "ACK"}}},
				{Type: "eml_data", Fields: &scenario.EMLDataFields{
					Headers: map[string]string{"Subject": "hi"},
					Body:    "body\r\n",
				}},
			},
		}},
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	read := readPackets(t, buf.Bytes())
	if len(read) != 1 {
		t.Fatalf("期望 1 个包，得到 %d", len(read))
	}
	p0 := read[0].ApplicationLayer()
	want := "Subject: hi\r\n\r\nbody\r\n.\r\n"
	if p0 == nil || string(p0.Payload()) != want {
		t.Errorf("包0 EML=%q,期望 %q", p0, want)
	}
}
