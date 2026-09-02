package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 IMAP 应用层序列化( builder/imap.go ):三形式命令(命令行 / 裸行 / literal
// 八位组)、响应三态(tagged / untagged / continuation)、状态组/数据组、literal 的
// {n}/{n+}/~{n} 前缀与 emit 三态,断言字节符合 RFC 9051。走 PayloadBytes 与 serializeStack
// 同一序列化路径,确保行为一致。

func boolPtr(v bool) *bool { return &v }

func TestSerializeIMAPReq_CommandLine(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.IMAPRequestFields
		want string
	}{
		{"NOOP 无 args", scenario.IMAPRequestFields{Tag: "a001", Command: "NOOP"}, "a001 NOOP\r\n"},
		{"LOGIN 带 args", scenario.IMAPRequestFields{Tag: "a001", Command: "LOGIN", Args: "alice secret"}, "a001 LOGIN alice secret\r\n"},
		{"小写命令原样输出", scenario.IMAPRequestFields{Tag: "a001", Command: "login", Args: "alice secret"}, "a001 login alice secret\r\n"},
		{"tag 含 ] 原样输出", scenario.IMAPRequestFields{Tag: "tag]x", Command: "NOOP"}, "tag]x NOOP\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeIMAPReq_BareLine(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.IMAPRequestFields
		want string
	}{
		{"IDLE DONE", scenario.IMAPRequestFields{Line: "DONE"}, "DONE\r\n"},
		{"SASL base64 续行", scenario.IMAPRequestFields{Line: "AGFsaWNlAHBhc3M="}, "AGFsaWNlAHBhc3M=\r\n"},
		{"取消 literal 的 *", scenario.IMAPRequestFields{Line: "*"}, "*\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeIMAPReq_LiteralEmit(t *testing.T) {
	// 形式 A + literal emit=full:tag SP command SP {n}\r\n<data>\r\n
	fFull := scenario.IMAPRequestFields{
		Tag: "a003", Command: "APPEND", Args: `INBOX (\Seen) "23-Oct-2024 12:00:00 +0000"`,
		Literal: &scenario.IMAPLiteral{Data: "hello", Emit: "full"},
	}
	wantFull := `a003 APPEND INBOX (\Seen) "23-Oct-2024 12:00:00 +0000" {5}` + "\r\nhello\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &fFull}); !bytes.Equal(got, []byte(wantFull)) {
		t.Errorf("emit=full = %q, want %q", got, wantFull)
	}

	// emit=prefix:仅 {n}\r\n,无数据,无命令终止 CRLF(prefix 自带 CRLF)。
	fPrefix := scenario.IMAPRequestFields{
		Tag: "a003", Command: "APPEND", Args: `INBOX`,
		Literal: &scenario.IMAPLiteral{Data: "hello", Emit: "prefix"},
	}
	wantPrefix := "a003 APPEND INBOX {5}\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &fPrefix}); !bytes.Equal(got, []byte(wantPrefix)) {
		t.Errorf("emit=prefix = %q, want %q", got, wantPrefix)
	}

	// emit=data:仅数据 + CRLF(同步 literal 第③段)。
	fData := scenario.IMAPRequestFields{
		Literal: &scenario.IMAPLiteral{Data: "hello", Emit: "data"},
	}
	wantData := "hello\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &fData}); !bytes.Equal(got, []byte(wantData)) {
		t.Errorf("emit=data = %q, want %q", got, wantData)
	}

	// literal 为首个参数(args 空):tag SP command SP {n}\r\n<data>\r\n。
	fFirst := scenario.IMAPRequestFields{
		Tag: "a001", Command: "LOGIN",
		Literal: &scenario.IMAPLiteral{Data: "abc", Emit: "full"},
	}
	wantFirst := "a001 LOGIN {3}\r\nabc\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &fFirst}); !bytes.Equal(got, []byte(wantFirst)) {
		t.Errorf("literal 首参数 = %q, want %q", got, wantFirst)
	}
}

func TestSerializeIMAPReq_LiteralNonSync(t *testing.T) {
	// 非同步 {n+}:client→server,不等待 +。
	f := scenario.IMAPRequestFields{
		Tag: "a001", Command: "APPEND", Args: "INBOX",
		Literal: &scenario.IMAPLiteral{Data: "hi", Sync: boolPtr(false), Emit: "full"},
	}
	want := "a001 APPEND INBOX {2+}\r\nhi\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &f}); !bytes.Equal(got, []byte(want)) {
		t.Errorf("非同步 literal = %q, want %q", got, want)
	}
}

func TestSerializeIMAPReq_LiteralOctetsOverride(t *testing.T) {
	// octets 覆盖:声明 9999 而实际 5 字节,原样落值(关闭自动计算)。
	n := 9999
	f := scenario.IMAPRequestFields{
		Tag: "a001", Command: "APPEND", Args: "INBOX",
		Literal: &scenario.IMAPLiteral{Data: "hello", Octets: &n, Emit: "full"},
	}
	want := "a001 APPEND INBOX {9999}\r\nhello\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &f}); !bytes.Equal(got, []byte(want)) {
		t.Errorf("octets 覆盖 = %q, want %q", got, want)
	}
}

func TestSerializeIMAPReq_LiteralEML(t *testing.T) {
	// literal 内容走 eml 子结构:复用 SerializeEMLData 纯内容,IMAP 加 {n} 前缀,
	// 不做 dot-stuffing / 终止符。
	eml := &scenario.EMLDataFields{
		Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
		Body:    "hi",
	}
	f := scenario.IMAPRequestFields{
		Tag: "a001", Command: "APPEND", Args: "INBOX",
		Literal: &scenario.IMAPLiteral{EML: eml, Emit: "full"},
	}
	// eml 内容:"From: a@b\r\n\r\nhi" = 15 字节。
	want := "a001 APPEND INBOX {15}\r\nFrom: a@b\r\n\r\nhi\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_request", Fields: &f}); !bytes.Equal(got, []byte(want)) {
		t.Errorf("literal eml = %q, want %q", got, want)
	}
}

func TestSerializeIMAPResp_Status(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.IMAPResponseFields
		want string
	}{
		{"tagged OK", scenario.IMAPResponseFields{Tag: "a001", Status: "OK", Text: "LOGIN completed"}, "a001 OK LOGIN completed\r\n"},
		{"untagged OK 带 code", scenario.IMAPResponseFields{Tag: "*", Status: "OK", Code: "UIDVALIDITY 3857529045", Text: "UIDs valid"}, "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n"},
		{"untagged PREAUTH", scenario.IMAPResponseFields{Tag: "*", Status: "PREAUTH", Text: "Already authenticated"}, "* PREAUTH Already authenticated\r\n"},
		{"untagged BYE 无 text", scenario.IMAPResponseFields{Tag: "*", Status: "BYE"}, "* BYE\r\n"},
		{"tagged OK 无 code 无 text", scenario.IMAPResponseFields{Tag: "a001", Status: "OK"}, "a001 OK\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "imap_response", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeIMAPResp_Continuation(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.IMAPResponseFields
		want string
	}{
		{"continuation 带 text", scenario.IMAPResponseFields{Tag: "+", Text: "Ready for literal data"}, "+ Ready for literal data\r\n"},
		{"continuation 空 text(base64 挑战为空)", scenario.IMAPResponseFields{Tag: "+", Text: ""}, "+ \r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "imap_response", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeIMAPResp_Data(t *testing.T) {
	// 数据形式:untagged EXISTS(无 literal)。
	fExists := scenario.IMAPResponseFields{Tag: "*", Data: "42 EXISTS"}
	wantExists := "* 42 EXISTS\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_response", Fields: &fExists}); !bytes.Equal(got, []byte(wantExists)) {
		t.Errorf("EXISTS = %q, want %q", got, wantExists)
	}

	// 数据形式 + literal + tail:RFC 9051 §6.4.5 FETCH BODY[] 形态。
	// "* 12 FETCH (BODY[] {5}\r\nhello)\r\n" —— literal 数据与 tail 间无额外 CRLF。
	fFetch := scenario.IMAPResponseFields{
		Tag: "*", Data: "12 FETCH (BODY[] ",
		Literal: &scenario.IMAPLiteral{Data: "hello"}, Tail: ")",
	}
	wantFetch := "* 12 FETCH (BODY[] {5}\r\nhello)\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_response", Fields: &fFetch}); !bytes.Equal(got, []byte(wantFetch)) {
		t.Errorf("FETCH = %q, want %q", got, wantFetch)
	}
}

func TestSerializeIMAPResp_LiteralBinary(t *testing.T) {
	// literal8(~{n}):BINARY FETCH 响应,仅 server→client。
	f := scenario.IMAPResponseFields{
		Tag: "*", Data: "12 FETCH (BINARY[] ",
		Literal: &scenario.IMAPLiteral{DataHex: "0x01020304", Binary: true}, Tail: ")",
	}
	want := "* 12 FETCH (BINARY[] ~{4}\r\n\x01\x02\x03\x04)\r\n"
	if got, _ := builder.PayloadBytes(scenario.Layer{Type: "imap_response", Fields: &f}); !bytes.Equal(got, []byte(want)) {
		t.Errorf("literal8 = %q, want %q", got, want)
	}
}

// TestSerializeIMAP_PayloadBytesVsSerializeStack: PayloadBytes 与 serializeStack 产出字节一致
// (flow messagePayload 靠 PayloadBytes 算 MSS 分段长度,两者不一致会让分段边界错位)。
func TestSerializeIMAP_PayloadBytesVsSerializeStack(t *testing.T) {
	layers := []scenario.Layer{
		{Type: "imap_request", Fields: &scenario.IMAPRequestFields{Tag: "a001", Command: "APPEND", Args: "INBOX",
			Literal: &scenario.IMAPLiteral{Data: "hello", Emit: "full"}}},
		{Type: "imap_response", Fields: &scenario.IMAPResponseFields{Tag: "*", Data: "12 FETCH (BODY[] ",
			Literal: &scenario.IMAPLiteral{Data: "hi"}, Tail: ")"}},
		{Type: "imap_request", Fields: &scenario.IMAPRequestFields{Line: "DONE"}},
	}
	for _, l := range layers {
		pb, err := builder.PayloadBytes(l)
		if err != nil {
			t.Fatalf("PayloadBytes(%s): %v", l.Type, err)
		}
		// 通过带 L2/L3/L4 stack 的 serializeStack 构造,取最内 payload 比对。
		stack := []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 143}},
			l,
		}
		outs, err := builder.BuildPlanned([]scenario.PlannedPacket{{Packet: scenario.Packet{Stack: stack}}})
		if err != nil {
			t.Fatalf("BuildPlanned(%s): %v", l.Type, err)
		}
		full := outs[0].Data
		// full 是整个以太帧;payload 字节应出现在末尾(tcp 头之后)。取 pb 作为子串断言。
		if !bytes.Contains(full, pb) {
			t.Errorf("serializeStack 未包含 PayloadBytes 字节:\nserializeStack=%q\nPayloadBytes=%q", full, pb)
		}
	}
}
