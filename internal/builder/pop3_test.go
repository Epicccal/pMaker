package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 POP3 应用层序列化:命令(command+args 扁平)、响应(单行 message / 多行 lines /
// 多行 eml 子结构),断言字节符合 RFC 1939(含 dot-stuffing + <CRLF>.<CRLF> 终止符)。走
// PayloadBytes 与 serializeStack 同一序列化路径,确保行为一致。

func TestSerializePOP3Req(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.POP3RequestFields
		want string
	}{
		{
			name: "USER 带 args",
			f:    scenario.POP3RequestFields{Command: "USER", Args: "alice"},
			want: "USER alice\r\n",
		},
		{
			name: "RETR 带 args",
			f:    scenario.POP3RequestFields{Command: "RETR", Args: "1"},
			want: "RETR 1\r\n",
		},
		{
			name: "TOP 两参数",
			f:    scenario.POP3RequestFields{Command: "TOP", Args: "1 10"},
			want: "TOP 1 10\r\n",
		},
		{
			name: "QUIT 无 args(不追加空格)",
			f:    scenario.POP3RequestFields{Command: "QUIT"},
			want: "QUIT\r\n",
		},
		{
			name: "小写命令原样输出",
			f:    scenario.POP3RequestFields{Command: "retr", Args: "1"},
			want: "retr 1\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "pop3_request", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSerializePOP3Resp(t *testing.T) {
	cases := []struct {
		name string
		f    scenario.POP3ResponseFields
		want string
	}{
		{
			name: "单行 message",
			f:    scenario.POP3ResponseFields{Status: "+OK", Message: "POP3 server ready"},
			want: "+OK POP3 server ready\r\n",
		},
		{
			name: "单行 -ERR",
			f:    scenario.POP3ResponseFields{Status: "-ERR", Message: "invalid user"},
			want: "-ERR invalid user\r\n",
		},
		{
			name: "裸 status 行(message 为空,无 lines/eml)→ 单行 status",
			// 校验拦截此形态(需要 message/lines/eml);裸 status 行应走 payload/payload_hex。
			// 此处仅验 builder 在 Lines=nil,EML=nil 时输出裸 status 行字节。
			f:    scenario.POP3ResponseFields{Status: "+OK"},
			want: "+OK\r\n",
		},
		{
			name: "message + lines(多行首行带说明文本,RFC 1939 §3 LIST 形态)",
			f: scenario.POP3ResponseFields{
				Status:  "+OK",
				Message: "2 messages (320 octets)",
				Lines:   []string{"1 1200", "2 2000"},
			},
			want: "+OK 2 messages (320 octets)\r\n1 1200\r\n2 2000\r\n.\r\n",
		},
		{
			name: "message + eml(多行首行带说明文本 + RFC 5322 正文)",
			f: scenario.POP3ResponseFields{
				Status:  "+OK",
				Message: "message 1 follows",
				EML: &scenario.EMLDataFields{
					Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
					Body:    "Hi.\r\n",
				},
			},
			want: "+OK message 1 follows\r\nFrom: a@b\r\n\r\nHi.\r\n.\r\n",
		},
		{
			name: "message + lines dot-stuff(正文行首 . → ..,status 文本不参与)",
			f: scenario.POP3ResponseFields{
				Status:  "+OK",
				Message: "listing",
				Lines:   []string{".hidden", "normal"},
			},
			want: "+OK listing\r\n..hidden\r\nnormal\r\n.\r\n",
		},
		{
			name: "多行 lines(LIST 扫描列表)+ 终止符",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				Lines:  []string{"1 1200", "2 2000"},
			},
			want: "+OK\r\n1 1200\r\n2 2000\r\n.\r\n",
		},
		{
			name: "多行 lines 含空行如实输出",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				Lines:  []string{"1 1200", "", "3 512"},
			},
			want: "+OK\r\n1 1200\r\n\r\n3 512\r\n.\r\n",
		},
		{
			name: "多行 lines dot-stuff(行首 . → ..)",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				Lines:  []string{".hidden", "normal"},
			},
			// ".hidden" 行首 . → "..hidden"(RFC 1939 §3 dot-stuffing)
			want: "+OK\r\n..hidden\r\nnormal\r\n.\r\n",
		},
		{
			name: "多行 CAPA 能力列表",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				Lines:  []string{"TOP", "USER", "SASL PLAIN LOGIN", "STLS", "UIDL"},
			},
			want: "+OK\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN\r\nSTLS\r\nUIDL\r\n.\r\n",
		},
		{
			name: "多行 eml 子结构(RETR RFC 5322 正文)",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				EML: &scenario.EMLDataFields{
					Headers: scenario.HeaderMap{
						{Key: "From", Value: "alice@example.com"},
						{Key: "Subject", Value: "Hello"},
					},
					Body: "Hi there.\r\n",
				},
			},
			// status 行 + eml 内容(headers + 空行 + body,自动 dot-stuff + 终止符)
			want: "+OK\r\nFrom: alice@example.com\r\nSubject: Hello\r\n\r\nHi there.\r\n.\r\n",
		},
		{
			name: "多行 eml dot-stuff(body 行首 . 被 stuff)",
			f: scenario.POP3ResponseFields{
				Status: "+OK",
				EML: &scenario.EMLDataFields{
					Headers: scenario.HeaderMap{{Key: "From", Value: "a@b"}},
					Body:    ".secret\r\n",
				},
			},
			want: "+OK\r\nFrom: a@b\r\n\r\n..secret\r\n.\r\n",
		},
		{
			name: "小写状态指示符原样输出",
			f:    scenario.POP3ResponseFields{Status: "+ok", Message: "ready"},
			want: "+ok ready\r\n",
		},
		{
			name: "SASL 续行挑战(单字符 +,RFC 1734/4954)",
			f:    scenario.POP3ResponseFields{Status: "+", Message: "AGFsaWNlAHNlY3JldA=="},
			want: "+ AGFsaWNlAHNlY3JldA==\r\n",
		},
		{
			name: "SASL 续行裸 +(无 message,裸 +\\r\\n 走 payload/payload_hex;此处仅验 message 为空的 status 单行)",
			f:    scenario.POP3ResponseFields{Status: "+", Message: ""},
			// Status="+" Message="" Lines=nil EML=nil → 校验拦截(需要 message/lines/eml);
			// 裸 +\r\n 应走 payload/payload_hex,不经此路径。
			// builder 在无 lines/eml 时退出单行路径,输出 "+\r\n",与 SASL 裸挑战的线格式一致,
			// 但合法路径是经由 message 携带 base64 挑战(见 "SASL 续行挑战" 用例)。
			want: "+\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "pop3_response", Fields: &c.f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Errorf("PayloadBytes = %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseBackPOP3 构造一个最小 eth/ipv4/tcp + pop3_request 包,回读断言 TCP payload
// 为命令字节,证明 pop3_request 经 serializeStack 序列化为 gopacket.Payload。
func TestParseBackPOP3(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.110", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 110, Flags: []string{"PSH", "ACK"}}},
				{Type: "pop3_request", Fields: &scenario.POP3RequestFields{Command: "RETR", Args: "1"}},
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
	if p0 == nil || string(p0.Payload()) != "RETR 1\r\n" {
		t.Errorf("包0 POP3 命令=%q,期望 RETR 1\\r\\n", p0)
	}
}
