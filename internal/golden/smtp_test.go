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

// TestEmailNestedMultipartWireFormat 验证嵌套 multipart 的 RFC 2046 线格式:
//   - 外层 boundary(outer_boundary)分隔符出现;
//   - 内层 boundary(inner_boundary)分隔符出现;
//   - 两层终止符(--boundary--)都存在;
//   - 纯文本 part 内容出现;
//   - HTML part 内容出现;
//   - base64 编码的附件出现;
//   - 所有 boundary 前后正确使用 CRLF。
func TestEmailNestedMultipartWireFormat(t *testing.T) {
	pcap := generatePcap(t, "../../examples/email/multipart_nested_mixed_alternative.yaml")
	for _, want := range [][]byte{
		// 外层 multipart/mixed boundary
		[]byte("Content-Type: multipart/mixed; boundary=outer_boundary"),
		[]byte("--outer_boundary\r\n"),
		[]byte("--outer_boundary--\r\n"),
		// 内层 multipart/alternative boundary
		[]byte("Content-Type: multipart/alternative; boundary=inner_boundary"),
		[]byte("--inner_boundary\r\n"),
		[]byte("--inner_boundary--\r\n"),
		// 纯文本 part
		[]byte("Content-Type: text/plain; charset=utf-8"),
		[]byte("This is the plain text version."),
		// HTML part
		[]byte("Content-Type: text/html; charset=utf-8"),
		[]byte("This is the <b>HTML</b> version."),
		// 附件 part(base64 编码后)
		[]byte("Content-Type: application/octet-stream"),
		[]byte("Content-Disposition: attachment; filename=\"data.bin\""),
		[]byte("Content-Transfer-Encoding: base64"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestEmailThreeLevelNestedMultipart 验证三层嵌套 multipart 的递归序列化:
//   - 最外层 level1 boundary;
//   - 中层 level2 boundary;
//   - 最内层 level3 boundary;
//   - 所有三层都有对应终止符;
//   - HTML 正文与 PNG 内联图片(CID 引用)出现;
//   - PDF 附件 base64 编码出现。
func TestEmailThreeLevelNestedMultipart(t *testing.T) {
	pcap := generatePcap(t, "../../examples/email/multipart_three_levels.yaml")
	for _, want := range [][]byte{
		// 三层 boundary 分界符
		[]byte("--level1\r\n"),
		[]byte("--level2\r\n"),
		[]byte("--level3\r\n"),
		// 三层终止符
		[]byte("--level1--\r\n"),
		[]byte("--level2--\r\n"),
		[]byte("--level3--\r\n"),
		// HTML 正文
		[]byte("<html><body><img src=\"cid:img1\"/>"),
		// 内联图片 CID
		[]byte("Content-ID: <img1>"),
		// PNG 魔术头(0x89504e47 hex → base64 encoded)
		[]byte("iVBORw=="),
		// PDF 附件("JVBERi0xLjQK" plain text → base64 encoded)
		[]byte("Content-Disposition: attachment; filename=\"doc.pdf\""),
		[]byte("SlZCRVJpMHhMalFL"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestEmailBoundaryCollisionWarning 验证 boundary 碰撞软告警机制:
// pcap 正常生成,但 part body 内含独占一行的 boundary 分界符会触发软告警。
// 此测试只验证 pcap 字节正确,软告警由 CLI 输出验证(已在 gen 测试确认)。
func TestEmailBoundaryCollisionWarning(t *testing.T) {
	pcap := generatePcap(t, "../../examples/email/multipart_boundary_collision.yaml")
	for _, want := range [][]byte{
		// boundary 分界符
		[]byte("--simple\r\n"),
		[]byte("--simple--\r\n"),
		// 正常 part
		[]byte("This is normal content."),
		// 碰撞 part:body 内也出现 --simple(解析端会误切)
		[]byte("Start of content"),
		[]byte("--simple"),
		[]byte("This line looks like boundary!"),
		[]byte("End of content"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}
