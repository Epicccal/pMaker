package golden_test

import (
	"bytes"
	"testing"
)

// TestPOP3AuthRetrContent 回读 auth_retr,断言 USER/PASS/STAT/LIST/RETR/DELE/QUIT 命令、
// 单行响应、多行 LIST(lines)+ 终止符、多行 RETR(eml 子结构,自动 dot-stuff + 终止符)
// 均出现在 pcap 里。
func TestPOP3AuthRetrContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/auth_retr.yaml")
	for _, want := range [][]byte{
		// 服务器问候(含 APOP 时间戳)
		[]byte("+OK POP3 server ready <1896.697170952@mail.example>\r\n"),
		// 命令
		[]byte("USER alice\r\n"),
		[]byte("PASS secret\r\n"),
		[]byte("STAT\r\n"),
		[]byte("LIST\r\n"),
		[]byte("RETR 1\r\n"),
		[]byte("DELE 2\r\n"),
		[]byte("QUIT\r\n"),
		// 单行响应
		[]byte("+OK User accepted\r\n"),
		[]byte("+OK Maildrop locked and ready\r\n"),
		[]byte("+OK 2 3200\r\n"),
		// 多行 LIST(首行带说明文本 + lines + 终止符)
		[]byte("+OK 2 messages (3200 octets)\r\n1 1200\r\n2 2000\r\n.\r\n"),
		// 多行 RETR(首行带说明文本 + eml 子结构:headers + 空行 + body + 终止符)
		[]byte("+OK message 1 follows\r\nFrom: alice@example.com\r\nTo: bob@example.net\r\nSubject: Hello\r\nDate: Thu, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\nHi Bob,\r\nThis is a test message.\r\n"),
		// RETR 正文行首 . 被 dot-stuff("..\r\n"),末尾终止符 ".\r\n"
		[]byte("..\r\nCheers,\r\nAlice\r\n.\r\n"),
		// DELE / QUIT 响应
		[]byte("+OK message 2 deleted\r\n"),
		[]byte("+OK bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3STLSContent 回读 stls,断言 CAPA 命令/多行能力响应(含 STLS/SASL/UIDL)、
// STLS 命令与 +OK Begin TLS negotiation 响应均出现在 pcap 里。
func TestPOP3STLSContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/stls.yaml")
	for _, want := range [][]byte{
		[]byte("CAPA\r\n"),
		// 多行 CAPA 能力响应(首行带说明文本 + 能力列表,逐行 dot-stuff + 终止符)
		[]byte("+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN CRAM-MD5\r\nRESP-CODES\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\nSTLS\r\n.\r\n"),
		[]byte("STLS\r\n"),
		[]byte("+OK Begin TLS negotiation\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3MalformedContent 回读 malformed,断言四类畸形字节均出现在 pcap 里
// (私有命令走 payload_hex、小写命令走结构化路径、CRLF 注入走结构化路径、非标状态指示符走 payload_hex)。
func TestPOP3MalformedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/malformed.yaml")
	for _, want := range [][]byte{
		// ① 私有命令 XLIST(payload_hex)
		[]byte("XLIST\r\n"),
		// ② 小写命令(结构化路径原样输出)
		[]byte("retr 1\r\n"),
		// ③ CRLF 注入(结构化路径,args 原样输出)
		[]byte("USER alice\r\nDELE 1\r\n\r\n"),
		// ④ 非标状态指示符 +FOO(payload_hex)
		[]byte("+FOO bar\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3AuthSASLContent 回读 auth_sasl,断言 SASL 续行挑战(单字符 + 开头,
// RFC 1734/4954)、客户端 base64 凭证、CAPA 含 SASL 能力、认证成功响应均出现在 pcap 里。
func TestPOP3AuthSASLContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/auth_sasl.yaml")
	for _, want := range [][]byte{
		// CAPA 命令
		[]byte("CAPA\r\n"),
		// CAPA 多行响应(首行带说明文本 + 能力列表,含 SASL)
		[]byte("+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN CRAM-MD5\r\nRESP-CODES\r\nPIPELINING\r\nUIDL\r\nSTLS\r\n.\r\n"),
		// AUTH PLAIN 发起
		[]byte("AUTH PLAIN\r\n"),
		// 服务器 SASL 续行挑战(单字符 + 开头,非 +OK;message 承载 base64 挑战)
		[]byte("+ AGFsaWNlAHNlY3JldA==\r\n"),
		// 客户端 SASL 续行响应:一行裸 base64(RFC 1734 §3,无命令前缀)
		[]byte("AGFsaWNlAHNlY3JldA==\r\n"),
		// 认证成功
		[]byte("+OK authentication successful\r\n"),
		// QUIT
		[]byte("QUIT\r\n"),
		[]byte("+OK bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3RetrFileContent 验证 pop3/retr_file 示例:
//   - @file(assets/sample.eml) 把真实邮件注入 pop3_response.eml.raw;
//   - 客户端命令(RETR 1)与服务端状态行(+OK ... octets)出现在 pcap;
//   - sample.eml 特征内容与 smtp/eml_file 对称(同一份文件);
//   - 接入层追加 dot-stuffing 终止符(<CRLF>.<CRLF>)。
func TestPOP3RetrFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/retr_file.yaml")
	for _, want := range [][]byte{
		// 客户端命令
		[]byte("RETR 1\r\n"),
		// 服务端状态行
		[]byte("+OK 106458 octets\r\n"),
		// sample.eml 特征头(与 smtp/eml_file 对称验证同一份文件被正确注入)
		[]byte("From: \"=?utf-8?B?dXNlckE=?=\" <userA@qq.com>"),
		[]byte(`boundary="----=_NextPart_6A841ABB_A38AD000_73F0D3C0"`),
		[]byte("X-Mailer: QQMail 2.x"),
		// POP3 RETR 成帧:dot-stuffing 终止符
		[]byte("\r\n.\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}
