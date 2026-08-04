package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 SMTP 应用层序列化:命令(结构化 MAIL/RCPT + args 普通参数)、
// 响应(单行/多行,含空文本行),断言字节符合 RFC 5321。走 PayloadBytes 与 serializeStack
// 同一序列化路径,确保行为一致。

func strPtr(s string) *string { return &s }

func TestSerializeSMTPReq_MailStruct(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.SMTPRequestFields
		want string
	}{
		{
			name: "MAIL 地址 + params 排序",
			f: scenario.SMTPRequestFields{
				Verb:   "MAIL",
				From:   strPtr("a@b"),
				Params: map[string]string{"SMTPUTF8": "", "SIZE": "10"},
			},
			// 字典序 SIZE < SMTPUTF8;SMTPUTF8 裸键、SIZE 带值
			want: "MAIL FROM:<a@b> SIZE=10 SMTPUTF8\r\n",
		},
		{
			name: "MAIL 退信空 from",
			f: scenario.SMTPRequestFields{
				Verb: "MAIL",
				From: strPtr(""),
			},
			want: "MAIL FROM:<>\r\n",
		},
		{
			name: "MAIL 无 params",
			f: scenario.SMTPRequestFields{
				Verb: "MAIL",
				From: strPtr("alice@example.com"),
			},
			want: "MAIL FROM:<alice@example.com>\r\n",
		},
		{
			name: "RCPT 地址 + params",
			f: scenario.SMTPRequestFields{
				Verb:   "RCPT",
				To:     "bob@example.net",
				Params: map[string]string{"NOTIFY": "SUCCESS,FAILURE"},
			},
			want: "RCPT TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE\r\n",
		},
		{
			name: "MAIL 地址含 CRLF 注入(裸透传)",
			f: scenario.SMTPRequestFields{
				Verb: "MAIL",
				From: strPtr("alice@example.com\r\nRSET\r\n"),
			},
			want: "MAIL FROM:<alice@example.com\r\nRSET\r\n>\r\n",
		},
		{
			name: "MAIL 小写 verb 原样输出",
			f: scenario.SMTPRequestFields{
				Verb: "mail",
				From: strPtr("a@b"),
			},
			want: "mail FROM:<a@b>\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "smtp_request", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeSMTPReq_ArgsVerbs(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.SMTPRequestFields
		want string
	}{
		{"EHLO 域名", scenario.SMTPRequestFields{Verb: "EHLO", Args: "client.example"}, "EHLO client.example\r\n"},
		{"DATA 裸 verb", scenario.SMTPRequestFields{Verb: "DATA"}, "DATA\r\n"},
		{"QUIT 裸 verb", scenario.SMTPRequestFields{Verb: "QUIT"}, "QUIT\r\n"},
		{"AUTH PLAIN", scenario.SMTPRequestFields{Verb: "AUTH", Args: "PLAIN dGVzdA=="}, "AUTH PLAIN dGVzdA==\r\n"},
		{"STARTTLS 裸", scenario.SMTPRequestFields{Verb: "STARTTLS"}, "STARTTLS\r\n"},
		{"BDAT chunk-size", scenario.SMTPRequestFields{Verb: "BDAT", Args: "1000 LAST"}, "BDAT 1000 LAST\r\n"},
		{"NOOP 带回显串", scenario.SMTPRequestFields{Verb: "NOOP", Args: "ping"}, "NOOP ping\r\n"},
		{"RSET 裸", scenario.SMTPRequestFields{Verb: "RSET"}, "RSET\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "smtp_request", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializeSMTPResp(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.SMTPResponseFields
		want string
	}{
		{
			name: "单行 message",
			f:    scenario.SMTPResponseFields{Code: 220, Message: "mail.example ESMTP"},
			want: "220 mail.example ESMTP\r\n",
		},
		{
			name: "多行 EHLO 响应(RFC 5321 每行带 code-)",
			f: scenario.SMTPResponseFields{
				Code:  250,
				Lines: []string{"mail.example", "PIPELINING", "SIZE 10485760", "STARTTLS", "AUTH PLAIN LOGIN", "8BITMIME"},
			},
			want: "250-mail.example\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
		},
		{
			name: "lines 含空元素如实输出",
			f: scenario.SMTPResponseFields{
				Code:  250,
				Lines: []string{"mail.example", "", "SIZE 10485760"},
			},
			want: "250-mail.example\r\n250-\r\n250 SIZE 10485760\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "smtp_response", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseBackSMTP 构造一个最小 eth/ipv4/tcp + smtp_request 包,回读断言 TCP payload
// 为结构化 MAIL 命令字节,证明 smtp_request 经 serializeStack 序列化为 gopacket.Payload。
func TestParseBackSMTP(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.25", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 25, Flags: []string{"PSH", "ACK"}}},
				{Type: "smtp_request", Fields: &scenario.SMTPRequestFields{Verb: "MAIL", From: strPtr("alice@example.com")}},
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
	p0 := read[0].ApplicationLayer()
	if p0 == nil || string(p0.Payload()) != "MAIL FROM:<alice@example.com>\r\n" {
		t.Errorf("包0 SMTP 命令=%q,期望 MAIL FROM:<alice@example.com>\\r\\n", p0)
	}
}
