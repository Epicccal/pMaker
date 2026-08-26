package golden_test

import (
	"bytes"
	"testing"
)

// TestSMTPEhloSendContent 回读 ehlo_send,断言多行 EHLO 响应(RFC 5321 每行带 250- 前缀)、
// 结构化 MAIL/RCPT 路径(from/to + params 按声明顺序输出)、DATA 正文走 payload 均出现在 pcap 里。
func TestSMTPEhloSendContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/ehlo_send.yaml")
	for _, want := range [][]byte{
		// 服务器 220 问候
		[]byte("220 mail.example ESMTP\r\n"),
		// EHLO 命令
		[]byte("EHLO client.example\r\n"),
		// 多行 EHLO 响应(每行带 250- 前缀,末行 250 SP text)
		[]byte("250-mail.example\r\n"),
		[]byte("250-PIPELINING\r\n"),
		[]byte("250-SIZE 10485760\r\n"),
		[]byte("250-STARTTLS\r\n"),
		[]byte("250-AUTH PLAIN LOGIN\r\n"),
		[]byte("250 8BITMIME\r\n"),
		// 结构化 MAIL:params 按 YAML 声明顺序输出(SIZE < BODY)
		[]byte("MAIL FROM:<alice@example.com> SIZE=1234 BODY=8BITMIME\r\n"),
		// 结构化 RCPT
		[]byte("RCPT TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE\r\n"),
		// DATA / 354
		[]byte("DATA\r\n"),
		[]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"),
		// 正文(payload 兜底)
		[]byte("From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nbody\r\n.\r\n"),
		// 250 queued / QUIT / 221
		[]byte("250 queued as ABC123\r\n"),
		[]byte("QUIT\r\n"),
		[]byte("221 bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestSMTPEhloEmptyLineContent 回读 ehlo_empty_line,断言多行响应中的空文本行如实输出
// (serializeSMTPResp 不静默丢弃空元素):第二行应为 "250-\r\n"。
func TestSMTPEhloEmptyLineContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/ehlo_empty_line.yaml")
	want := []byte("250-mail.example\r\n250-\r\n250-SIZE 10485760\r\n250 PIPELINING\r\n")
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含空文本行的多行响应 %q", want)
	}
}

// TestSMTPMalformedContent 回读 malformed,断言四类畸形 envelope 字节均出现在 pcap 里
// (结构性畸形走 payload_hex、CRLF 注入走结构化路径、私有 verb 走 payload_hex、
// 小写 verb 走结构化路径、越界响应码走 payload_hex)。
func TestSMTPMalformedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/malformed.yaml")
	for _, want := range [][]byte{
		// ① 结构性畸形:缺 <> 的 MAIL FROM(payload_hex)
		[]byte("MAIL FROM:alice@example.com  SIZE=10\r\n"),
		// ② 地址内容 CRLF 注入(结构化路径,<> 框照常包裹)
		[]byte("MAIL FROM:<alice@example.com\r\nRSET\r\n>\r\n"),
		// ③ 私有 verb XMSG(payload_hex)
		[]byte("XMSG stuff\r\n"),
		// ④ 小写 verb(结构化路径原样输出)
		[]byte("rcpt TO:<bob@example.net>\r\n"),
		// ⑤ 越界响应码 99(payload_hex)
		[]byte("99 oops\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestSMTPEmlFileContent 验证 smtp/eml_file 示例:
//   - @file(assets/sample.eml) 把真实邮件注入 eml_data.raw;
//   - 信封命令(MAIL FROM / RCPT TO / DATA)出现在 pcap;
//   - sample.eml 特征内容(From/To 头、multipart boundary、X-Mailer)出现在 pcap;
//   - 接入层追加 dot-stuffing 终止符(<CRLF>.<CRLF>)。
func TestSMTPEmlFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/eml_file.yaml")
	for _, want := range [][]byte{
		// 信封命令
		[]byte("MAIL FROM:<userA@qq.com>"),
		[]byte("RCPT TO:<userB@qq.com>"),
		[]byte("DATA\r\n"),
		// sample.eml 特征头
		[]byte("From: \"=?utf-8?B?dXNlckE=?=\" <userA@qq.com>"),
		[]byte("To: \"=?utf-8?B?dXNlckI=?=\" <userB@qq.com>"),
		[]byte(`boundary="----=_NextPart_6A841ABB_A38AD000_73F0D3C0"`),
		[]byte("X-Mailer: QQMail 2.x"),
		// SMTP DATA 成帧:dot-stuffing 终止符
		[]byte("\r\n.\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}
