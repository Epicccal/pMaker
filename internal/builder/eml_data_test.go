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
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "alice@example.com"},
			{Key: "To", Value: "bob@example.net"},
			{Key: "Subject", Value: "Hello"},
		},
		Body: "This is the email body.\r\nSecond line.\r\n",
	}
	// headers 按 YAML 声明顺序：From/To/Subject
	want := "From: alice@example.com\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: Hello\r\n" +
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
	// dot_stuff 缺省 on：body 行首 . → ..
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "Subject", Value: "t"}},
		Body:    ".hidden dot\r\nnormal line\r\n",
	}
	want := "Subject: t\r\n\r\n..hidden dot\r\nnormal line\r\n.\r\n"
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
		Headers:  scenario.HeaderMap{{Key: "Subject", Value: "t"}},
		Body:     ".hidden dot\r\nnormal line\r\n",
		DotStuff: "off",
	}
	want := "Subject: t\r\n\r\n.hidden dot\r\nnormal line\r\n.\r\n"
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
		Headers:  scenario.HeaderMap{{Key: "Subject", Value: "t"}},
		Body:     ".\r\nafter\r\n",
		DotStuff: "on",
	}
	// 结构化模式：headers + "\r\n" + body；dot_stuff 后 body 行首 . → ..；终止符 .\r\n
	want := "Subject: t\r\n\r\n..\r\nafter\r\n.\r\n"
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
		Headers:      scenario.HeaderMap{{Key: "Subject", Value: "no term"}},
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
		Headers: scenario.HeaderMap{
			{Key: "X-Custom", Value: "value\r\nInjected: header"},
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

func TestSerializeEMLData_BodyEmpty_HeadersOnly(t *testing.T) {
	// body 为空 + headers 非空 → headers + 空行（headers 末尾 \r\n 即空行）+ 终止符
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "Subject", Value: "empty body"}},
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

// TestSerializeEMLData_DuplicateHeaders 断言结构化模式保留重复头(如多个 Received)
// 并按 YAML 声明顺序全部输出,不去重、不排序。
func TestSerializeEMLData_DuplicateHeaders(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "Received", Value: "from mx1 by mx2"},
			{Key: "Received", Value: "from mx2 by mx3"},
			{Key: "From", Value: "a@b"},
		},
		Body:         "body\r\n",
		DotTerminate: "off",
		DotStuff:     "off",
	}
	want := "Received: from mx1 by mx2\r\n" +
		"Received: from mx2 by mx3\r\n" +
		"From: a@b\r\n" +
		"\r\n" +
		"body\r\n"
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
		Headers:  scenario.HeaderMap{{Key: "Subject", Value: "t"}},
		Body:     "line1\r\n\r\n\r\nline2\r\n",
		DotStuff: "on",
	}
	// 结构化：headers + "\r\n" + body；dot-stuffing 不改空行；终止符 .\r\n
	want := "Subject: t\r\n\r\nline1\r\n\r\n\r\nline2\r\n.\r\n"
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
					Headers: scenario.HeaderMap{{Key: "Subject", Value: "hi"}},
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

// TestSerializeEMLData_BodyBareLF_Normalized 断言结构化模式把 body 的裸 \n
// 归一化为 \r\n（模拟用户用 YAML `|` 块标量写入多行 body 的常见场景）。
func TestSerializeEMLData_BodyBareLF_Normalized(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		// body 用裸 \n 换行（如 YAML `|` 块标量产出）
		Body: "first line\n... and more\n",
	}
	// 归一化后 body → "first line\r\n... and more\r\n"，
	// dot_stuff=on 把行首 . → ..，再追加终止符
	want := "From: a@b\r\n\r\nfirst line\r\n.... and more\r\n.\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeEMLData_BodyMixedLF_Normalized 断言混用 \n 与 \r\n 时只归一化裸 \n，
// 已有的 \r\n 不动（不会变成 \r\r\n）。
func TestSerializeEMLData_BodyMixedLF_Normalized(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers:      scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		Body:         "line1\r\nline2\nline3\r\n",
		DotTerminate: "off",
		DotStuff:     "off",
	}
	// 第二行裸 \n → \r\n，其余 \r\n 不动
	want := "From: a@b\r\n\r\nline1\r\nline2\r\nline3\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeEMLData_BodyLeadingBareLF_Normalized 断言 body 以裸 \n 开头时也归一化。
func TestSerializeEMLData_BodyLeadingBareLF_Normalized(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers:      scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		Body:         "\nbody\n",
		DotTerminate: "off",
		DotStuff:     "off",
	}
	// 开头裸 \n → \r\n，末尾裸 \n → \r\n
	want := "From: a@b\r\n\r\n\r\nbody\r\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeEMLData_RawBareLF_NotNormalized 断言 raw 模式不归一化裸 \n
// （raw 保留精确字节，构造非标换行畸形）。
func TestSerializeEMLData_RawBareLF_NotNormalized(t *testing.T) {
	f := &scenario.EMLDataFields{
		Raw:          "first line\n... and more\n",
		DotStuff:     "off",
		DotTerminate: "off",
	}
	// raw 模式：裸 \n 原样保留，不归一化
	want := "first line\n... and more\n"
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---- multipart 经 eml_data 层的端到端序列化 ----
// 单元级 multipart+EML 序列化(boundary/dot-stuff/终止符)见 multipart_test.go 的
// TestSerializeMultipart_EMLMultipart / TestSerializeMultipart_EMLDotStuffOnPartBody。
// 此处补 eml_data builder 的分派路径:multipart 取代字面 body、Content-Type 顶层头、
// multipart + dot_terminate=off(无终止符)、multipart + dot_stuff=off(不 stuff)。

// TestSerializeEMLData_MultipartReplaceBody 断言 eml_data 设 multipart 时 body 取自
// serializeMultipart(取代字面 body),顶层头 + 空行 + multipart 字节 + 终止符。
func TestSerializeEMLData_MultipartReplaceBody(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "MIME-Version", Value: "1.0"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=bnd"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "bnd",
			Parts: []scenario.MultipartPart{{
				Headers: scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
				Body:    "part\r\n",
			}},
		},
	}
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	want := "From: a@b\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=bnd\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"part\r\n" +
		"\r\n" +
		"--bnd--\r\n" +
		".\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeEMLData_MultipartDotTerminateOff 断言 multipart 邮件也能用 dot_terminate=off
// 去掉终止符(IMAP 场景或畸形),multipart 字节原样输出不再追加 .\r\n。
func TestSerializeEMLData_MultipartDotTerminateOff(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=bnd"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "bnd",
			Parts:    []scenario.MultipartPart{{Body: "x"}},
		},
		DotStuff:     "off",
		DotTerminate: "off",
	}
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	want := "From: a@b\r\n" +
		"Content-Type: multipart/mixed; boundary=bnd\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"\r\n" +
		"x\r\n" +
		"--bnd--\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeEMLData_MultipartDotStuffOff 断言 dot_stuff=off 时 part body 行首 . 不被 stuff
// (构造 SMTP 传输透明性畸形),boundary 行 -- 开头本就不受影响。
func TestSerializeEMLData_MultipartDotStuffOff(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=bnd"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "bnd",
			Parts:    []scenario.MultipartPart{{Body: ".secret\r\n"}},
		},
		DotStuff:     "off",
		DotTerminate: "off",
	}
	got, err := builder.PayloadBytes(scenario.Layer{Type: "eml_data", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	// dot_stuff=off:part body 行首 . 原样保留(未被 stuff 成 ..)。
	if !bytes.Contains(got, []byte("\r\n.secret\r\n")) {
		t.Errorf("dot_stuff=off 应保留 part body 行首 .,got %q", got)
	}
	if bytes.Contains(got, []byte("\r\n..secret\r\n")) {
		t.Errorf("dot_stuff=off 不应 stuff 行首 .,got %q", got)
	}
}

// TestParseBackEMLData_MultipartE2E 端到端回读 eml_data(multipart)包,断言 TCP payload
// 含 multipart 分界符行、顶层 Content-Type 头与 SMTP 终止符 .\r\n。
func TestParseBackEMLData_MultipartE2E(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.25", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 25, Flags: []string{"PSH", "ACK"}}},
				{Type: "eml_data", Fields: &scenario.EMLDataFields{
					Headers: scenario.HeaderMap{
						{Key: "From", Value: "a@b"},
						{Key: "MIME-Version", Value: "1.0"},
						{Key: "Content-Type", Value: "multipart/mixed; boundary=----=_pMaker_0001"},
					},
					Multipart: &scenario.MultipartBody{
						Boundary: "----=_pMaker_0001",
						Parts: []scenario.MultipartPart{{
							Headers: scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
							Body:    "hi\r\n",
						}},
					},
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
		t.Fatalf("期望 1 个包,得到 %d", len(read))
	}
	app := read[0].ApplicationLayer()
	if app == nil {
		t.Fatal("缺应用层 payload")
	}
	for _, want := range []string{
		"Content-Type: multipart/mixed; boundary=----=_pMaker_0001",
		"------=_pMaker_0001\r\n",
		"------=_pMaker_0001--\r\n",
	} {
		if !bytes.Contains(app.Payload(), []byte(want)) {
			t.Errorf("payload 不含 %q, got %q", want, app.Payload())
		}
	}
	// SMTP 终止符 .\r\n 应在末尾(dot_terminate 默认 on)。
	if !bytes.HasSuffix(app.Payload(), []byte(".\r\n")) {
		t.Errorf("payload 应以 SMTP 终止符 .\\r\\n 结尾, got %q", app.Payload())
	}
}
