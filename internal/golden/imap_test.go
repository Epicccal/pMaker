package golden_test

import (
	"bytes"
	"testing"
)

// 本文件覆盖 IMAP 应用层端到端字节:回读 examples/imap/*.yaml 生成的 pcap,
// 断言 RFC 9051 关键字节序列出现(命令行 / 裸行 / continuation / 状态组 / 数据组 /
// literal {n}\r\n 前缀 / octets 撒谎 / payload_hex 兜底畸形)。

// TestIMAPSelectFetchContent 回读 select_fetch,断言 LOGIN/SELECT/FETCH/LOGOUT 命令、
// untagged 状态响应(OK [code] text)、untagged 数据响应(FLAGS/EXISTS/CAPABILITY)、
// FETCH literal({n}\r\n 前缀 + RFC 5322 内容 + tail)均出现在 pcap 里。
func TestIMAPSelectFetchContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/imap/select_fetch.yaml")
	for _, want := range [][]byte{
		// 服务器问候
		[]byte("* OK IMAP4rev2 Service Ready\r\n"),
		// CAPABILITY 命令 + untagged CAPABILITY 数据响应
		[]byte("a001 CAPABILITY\r\n"),
		[]byte("* CAPABILITY IMAP4rev1 IMAP4rev2 IDLE MOVE QUOTA\r\n"),
		[]byte("a001 OK CAPABILITY completed\r\n"),
		// LOGIN 命令 + tagged OK 带 code
		[]byte("a002 LOGIN alice secret\r\n"),
		[]byte("a002 OK [CAPABILITY IMAP4rev2 IDLE MOVE] LOGIN completed\r\n"),
		// SELECT 命令 + 多条 untagged(FLAGS/EXISTS/OK [UIDVALIDITY]) + tagged OK [READ-WRITE]
		[]byte("a003 SELECT INBOX\r\n"),
		[]byte("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"),
		[]byte("* 42 EXISTS\r\n"),
		[]byte("* OK [UIDVALIDITY 3857529045] UIDs valid\r\n"),
		[]byte("a003 OK [READ-WRITE] SELECT completed\r\n"),
		// FETCH 命令 + FETCH literal 响应(RFC 9051 §6.4.5 FETCH 命令形态)
		[]byte("a004 FETCH 1 BODY[]\r\n"),
		// literal 前缀:{n}\r\n(n = headers + 空行 + body 的字节数);n 由实际内容自动算。
		// data 文本 "1 FETCH (BODY[] " + "{n}\r\n" + eml 内容 + ")" + "\r\n"
		// 断言 eml 特征头出现在 pcap(IMAP literal 不做 dot-stuffing,原样)。
		[]byte("From: alice@example.com\r\n"),
		[]byte("Subject: Hello\r\n"),
		[]byte("Hi Bob,\r\nThis is a test message.\r\n"),
		// literal 数据后紧跟 tail ")",无额外 CRLF,再接命令终止 CRLF。
		[]byte(")\r\n"),
		[]byte("a004 OK FETCH completed\r\n"),
		// LOGOUT
		[]byte("a005 LOGOUT\r\n"),
		[]byte("* BYE IMAP4rev2 Server logging out\r\n"),
		[]byte("a005 OK LOGOUT completed\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestIMAPAppendLiteralContent 回读 append_literal,断言同步 literal 三段式:
// ① 命令行 + {n}\r\n(emit=prefix,无数据);② 服务器 + 续行;③ 八位组数据 + CRLF(emit=data)。
func TestIMAPAppendLiteralContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/imap/append_literal.yaml")
	for _, want := range [][]byte{
		// LOGIN / SELECT
		[]byte("a001 LOGIN alice secret\r\n"),
		[]byte("a002 SELECT INBOX\r\n"),
		// ① APPEND 命令行 + literal 前缀(emit=prefix,仅 {n}\r\n,无数据)
		[]byte("a003 APPEND INBOX (\\Seen) \"01-Jan-2024 12:00:00 +0000\" {"),
		// ② 服务器续行请求(continuation,+ 前缀)
		[]byte("+ Ready for literal data\r\n"),
		// ③ 八位组数据(emit=data)—— eml 内容 + 命令终止 CRLF
		[]byte("From: alice@example.com\r\n"),
		[]byte("Subject: Appended\r\n"),
		[]byte("Hello via APPEND.\r\n"),
		// APPEND 完成(tagged OK [APPENDUID])
		[]byte("a003 OK [APPENDUID 3857529045 100] APPEND completed\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestIMAPFetchFileContent 回读 fetch_file,断言 @file 占位符把外部 .eml 原始字节注入
// imap_response.literal.eml(raw 模式):literal 自动计数 {n}\r\n 前缀(n=106458)、
// eml 头/multipart boundary 原样出现(IMAP 无 dot-stuffing,字节精确)、tail 收尾。
// 与 smtp/eml_file.yaml、pop3/retr_file.yaml 同一份 sample.eml,上传/下载三方对称。
func TestIMAPFetchFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/imap/fetch_file.yaml")
	for _, want := range [][]byte{
		// LOGIN / SELECT
		[]byte("a001 LOGIN alice secret\r\n"),
		[]byte("a002 SELECT INBOX\r\n"),
		[]byte("* 1 EXISTS\r\n"),
		// FETCH 命令
		[]byte("a003 FETCH 1 BODY[]\r\n"),
		// literal 前缀:自动按 sample.eml 字节数算 n = 106458
		[]byte("1 FETCH (BODY[] {106458}\r\n"),
		// @file 注入的 eml 头原样出现(raw 模式:不归一化换行、不做 dot-stuffing)
		[]byte("From: \"=?utf-8?B?dXNlckE=?=\" <userA@qq.com>\r\n"),
		[]byte("Content-Type: multipart/mixed;\r\n"),
		[]byte("boundary=\"----=_NextPart_6A841ABB_A38AD000_73F0D3C0\"\r\n"),
		// multipart boundary 分界符原样出现
		[]byte("------=_NextPart_6A841ABB_A38AD000_73F0D3C0--\r\n"),
		// literal 末尾紧跟 tail ")",再接命令终止 CRLF
		[]byte(")\r\n"),
		[]byte("a003 OK FETCH completed\r\n"),
		// LOGOUT
		[]byte("a004 LOGOUT\r\n"),
		[]byte("* BYE IMAP4rev2 Server logging out\r\n"),
		[]byte("a004 OK LOGOUT completed\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestIMAPIdleDoneContent 回读 idle_done,断言 IDLE 命令、continuation 确认、
// 服务器主动 EXISTS 推送、裸行 DONE(形式 B 一等字段)均出现在 pcap 里。
func TestIMAPIdleDoneContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/imap/idle_done.yaml")
	for _, want := range [][]byte{
		// LOGIN / SELECT
		[]byte("a001 LOGIN alice secret\r\n"),
		[]byte("a002 SELECT INBOX\r\n"),
		[]byte("* 5 EXISTS\r\n"),
		// IDLE 命令(无 args)
		[]byte("a003 IDLE\r\n"),
		// 服务器 continuation 确认(+ 前缀)
		[]byte("+ idling\r\n"),
		// 服务器主动推送新邮件(untagged EXISTS)
		[]byte("* 6 EXISTS\r\n"),
		// 客户端裸行 DONE 退出 IDLE(形式 B)
		[]byte("DONE\r\n"),
		// IDLE 结束 tagged OK
		[]byte("a003 OK IDLE terminated\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestIMAPMalformedContent 回读 malformed,断言四类畸形字节均出现在 pcap 里:
// ① literal 计数撒谎({9999} 前缀);② literal 前缀后断连(仅 {5}\r\n);
// ③ 非法 tag(含 +,payload_hex);④ 缺空格状态行(payload_hex)。
func TestIMAPMalformedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/imap/malformed.yaml")
	for _, want := range [][]byte{
		// ① literal 计数撒谎:{9999}\r\n(实际 5 字节 "hello")
		[]byte("{9999}\r\nhello)\r\n"),
		// ② literal 前缀后断连:仅 {5}\r\n(无后续数据)
		[]byte("a001 APPEND INBOX {5}\r\n"),
		// ③ 非法 tag(含 +,payload_hex 手拼):a+1 NOOP\r\n
		[]byte("a+1 NOOP\r\n"),
		// ④ 缺空格状态行(payload_hex 手拼):* OK[UIDVALIDITY 1]UIDs valid\r\n
		[]byte("* OK[UIDVALIDITY 1]UIDs valid\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}
