package builder_test

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 multipart 序列化(serializeMultipart,经 PayloadBytes 端到端):boundary 行、
// part 头序、base64 76 列折行、quoted-printable、body_hex、终止 boundary 行、@file 注入。

func mustPayloadBytes(t *testing.T, l scenario.Layer) []byte {
	t.Helper()
	b, err := builder.PayloadBytes(l)
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	return b
}

func TestSerializeMultipart_BasicBoundary(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Method: "POST",
		URL:    "/u",
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts: []scenario.MultipartPart{{
				Headers: scenario.HeaderMap{
					{Key: "Content-Disposition", Value: `form-data; name="f"`},
				},
				Body: "v",
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	want := "POST /u HTTP/1.1\r\n" +
		"Content-Type: multipart/form-data; boundary=----=_pMaker_0001\r\n" +
		"\r\n" +
		"------=_pMaker_0001\r\n" +
		"Content-Disposition: form-data; name=\"f\"\r\n" +
		"\r\n" +
		"v\r\n" +
		"------=_pMaker_0001--\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSerializeMultipart_DefaultBoundary(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{Body: "x"}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	// 空 boundary → 默认 ----=_pMaker_0001;首行 = 请求行 + 空头 + 空行 + --boundary...
	if !bytes.Contains(got, []byte("------=_pMaker_0001\r\n")) {
		t.Errorf("缺默认 boundary 行,got %q", got)
	}
	if !bytes.Contains(got, []byte("------=_pMaker_0001--\r\n")) {
		t.Errorf("缺终止 boundary 行,got %q", got)
	}
}

func TestSerializeMultipart_TwoPartsOrder(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{
				{
					Headers: scenario.HeaderMap{
						{Key: "Content-Disposition", Value: `form-data; name="a"`},
						{Key: "Content-Type", Value: "text/plain"},
					},
					Body: "AAA",
				},
				{
					Headers: scenario.HeaderMap{
						{Key: "Content-Disposition", Value: `form-data; name="b"`},
					},
					Body: "BBB",
				},
			},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	// 两 part 按声明顺序:先 a 后 b;part 头按 HeaderMap 原序。
	want := "------=_pMaker_0001\r\n" +
		"Content-Disposition: form-data; name=\"a\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"AAA\r\n" +
		"------=_pMaker_0001\r\n" +
		"Content-Disposition: form-data; name=\"b\"\r\n" +
		"\r\n" +
		"BBB\r\n" +
		"------=_pMaker_0001--\r\n"
	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("got %q, want 含 %q", got, want)
	}
}

func TestSerializeMultipart_Base64Fold(t *testing.T) {
	// 200 字节 → base64 约 268 字符,应每 76 字符折行(\r\n 分隔)。
	body := strings.Repeat("A", 200)
	f := &scenario.HTTPReqFields{
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "base64"}},
				Body:     body,
				Encoding: "base64",
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	// 提取 part body:跳过 HTTP 请求头空行,再跳过 part 头空行,取到终止 boundary 前。
	// 结构:请求行+头\r\n\r\n --boundary\r\n part头\r\n\r\n {encoded} \r\n--boundary--\r\n
	// 找第二个 \r\n\r\n(part 头体分隔),再取到 \r\n--boundary-- 前。
	first := bytes.Index(got, []byte("\r\n\r\n")) + 4
	second := bytes.Index(got[first:], []byte("\r\n\r\n")) + first + 4
	end := bytes.Index(got[second:], []byte("\r\n------=_pMaker_0001--"))
	encoded := got[second : second+end]
	// 每行 ≤ 76 字符。
	for _, line := range bytes.Split(encoded, []byte("\r\n")) {
		if len(line) > 76 {
			t.Errorf("base64 折行后某行 %d 字符 > 76: %q", len(line), line)
		}
	}
	// 整体解码应还原原 body。
	encStr := strings.ReplaceAll(string(encoded), "\r\n", "")
	dec, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		t.Fatalf("base64 解码失败: %v", err)
	}
	if !bytes.Equal(dec, []byte(body)) {
		t.Errorf("base64 往返不一致")
	}
}

func TestSerializeMultipart_QuotedPrintable(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "quoted-printable"}},
				Body:     "café = test",
				Encoding: "quoted-printable",
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	// é (U+00E9) UTF-8 = 0xC3 0xA9 → QP =C3=A9;'=' → =3D。
	want := "caf=C3=A9 =3D test"
	if !bytes.Contains(got, []byte(want)) {
		t.Errorf("QP 编码结果 %q 不含 %q", got, want)
	}
}

// TestSerializeMultipart_IdentityEncodings 验证 RFC 2045 §6 恒等编码(7bit/8bit/binary)
// 原样透传 body 字节,不做任何变换(与 encoding: none 行为一致)。
func TestSerializeMultipart_IdentityEncodings(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		body     string
	}{
		{"7bit", "7bit", "ascii body"},
		{"8bit", "8bit", "café 高位"},
		{"binary", "binary", "raw bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &scenario.HTTPReqFields{
				Multipart: &scenario.MultipartBody{
					Parts: []scenario.MultipartPart{{
						Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: tc.encoding}},
						Body:     tc.body,
						Encoding: tc.encoding,
					}},
				},
			}
			got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
			// 恒等编码:body 原样出现在 part body(无 base64/QP 变换)。
			if !bytes.Contains(got, []byte("\r\n"+tc.body+"\r\n")) {
				t.Errorf("%s 恒等编码 body 未原样透传,got %q", tc.name, got)
			}
		})
	}
}

func TestSerializeMultipart_BodyHex(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{{
				BodyHex: "0x48656c6c6f", // "Hello"
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	if !bytes.Contains(got, []byte("\r\nHello\r\n")) {
		t.Errorf("body_hex 解码后未出现在 part body,got %q", got)
	}
}

func TestSerializeMultipart_ContentLengthAuto(t *testing.T) {
	f := &scenario.HTTPReqFields{
		AutoContentLength: true,
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"},
			{Key: "Content-Length", Value: "0"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts:    []scenario.MultipartPart{{Body: "payload"}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_request", Fields: f})
	// 计算预期 multipart body 长度。
	wantBody := "------=_pMaker_0001\r\n\r\npayload\r\n------=_pMaker_0001--\r\n"
	wantCL := "Content-Length: " + strconv.Itoa(len(wantBody))
	if !bytes.Contains(got, []byte(wantCL)) {
		t.Errorf("auto_content_length 未取 multipart 实际长度(%s),got %q", wantCL, got)
	}
}

// TestSerializeMultipart_AtFileInjection 经完整链路验证 @file 注入到 part body:
// 构造一个带 multipart 的 HTTP 请求,body 用 @file 引用 assets/form_field.txt。
func TestSerializeMultipart_AtFileInjection(t *testing.T) {
	pcap, _ := genPcap(t, "../../examples/http/multipart_form.yaml")
	// form_field.txt 内容 = "hello from pMaker\n";应原样出现在 pcap(不被 CRLF 归一化)。
	if !bytes.Contains(pcap, []byte("hello from pMaker\n")) {
		t.Errorf("pcap 不含 @file 注入的 part body 内容")
	}
	// 文本字段的 part body。
	if !bytes.Contains(pcap, []byte("text-value")) {
		t.Errorf("pcap 不含文本字段 part body")
	}
	// 文件字段的 Content-Disposition。
	if !bytes.Contains(pcap, []byte(`form-data; name="file"; filename="form_field.txt"`)) {
		t.Errorf("pcap 不含文件字段 Content-Disposition")
	}
}

// TestSerializeMultipart_EMLMultipart 验证 EML 下 multipart 作为 content 后仍正确 dot-stuff + 终止符。
func TestSerializeMultipart_EMLMultipart(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "MIME-Version", Value: "1.0"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=----=_pMaker_0001"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts: []scenario.MultipartPart{{
				Headers: scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
				Body:    "plain body\r\n",
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "eml_data", Fields: f})
	// 顶层头 → 空行 → multipart 字节 → 终止符 .\r\n。
	// part body "plain body\r\n" 末尾补 \r\n(再写下一个 boundary)→ "plain body\r\n\r\n"。
	want := "From: a@b\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=----=_pMaker_0001\r\n" +
		"\r\n" +
		"------=_pMaker_0001\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain body\r\n" +
		"\r\n" +
		"------=_pMaker_0001--\r\n" +
		".\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSerializeMultipart_EMLDotStuffOnPartBody 验证 dot-stuff 作用于编码后的整段 content
// (含 multipart 字节),part body 行首 . 被 stuff 成 ..;boundary 行 -- 开头不受影响。
func TestSerializeMultipart_EMLDotStuffOnPartBody(t *testing.T) {
	f := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{
			{Key: "From", Value: "a@b"},
			{Key: "Content-Type", Value: "multipart/mixed; boundary=----=_pMaker_0001"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts: []scenario.MultipartPart{{
				Body: ".secret dot line\r\n",
			}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "eml_data", Fields: f})
	// part body 行首 . → ..;终止符 .\r\n。
	if !bytes.Contains(got, []byte("..secret dot line\r\n")) {
		t.Errorf("dot-stuff 未作用于 part body 行首 .,got %q", got)
	}
	// boundary 行仍是 -- 开头(未被 stuff 成 .-)。
	if !bytes.Contains(got, []byte("------=_pMaker_0001\r\n")) {
		t.Errorf("boundary 行被错误 stuff,got %q", got)
	}
}

// TestParseBackMultipartHTTP_E2E 端到端:构造 eth/ipv4/tcp + http_request(multipart)包,
// 回读断言 TCP payload 含 multipart 分界符行,证明经 serializeStack 序列化正确。
func TestParseBackMultipartHTTP_E2E(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49160, DPort: 80, Flags: []string{"PSH", "ACK"}}},
				{Type: "http_request", Fields: &scenario.HTTPReqFields{
					Method: "POST",
					URL:    "/upload",
					Headers: scenario.HeaderMap{
						{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"},
					},
					Multipart: &scenario.MultipartBody{
						Boundary: "----=_pMaker_0001",
						Parts: []scenario.MultipartPart{{
							Headers: scenario.HeaderMap{{Key: "Content-Disposition", Value: `form-data; name="f"`}},
							Body:    "v",
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
		"POST /upload HTTP/1.1",
		"------=_pMaker_0001\r\n",
		"------=_pMaker_0001--\r\n",
		`form-data; name="f"`,
	} {
		if !bytes.Contains(app.Payload(), []byte(want)) {
			t.Errorf("payload 不含 %q, got %q", want, app.Payload())
		}
	}
}
