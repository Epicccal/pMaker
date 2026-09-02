package builder

import (
	"bytes"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/util/dotframe"
)

// serializePOP3Req 把一条 POP3 客户端命令序列化为 TCP payload 字节:COMMAND[ args]\r\n。
// command 原样输出(不强制大写),以便构造小写/非标命令等畸形用例(RFC 1939 §3 命令大小写
// 不敏感);args 为空时不追加空格。行尾统一 CRLF(RFC 1939)。
func serializePOP3Req(f *scenario.POP3RequestFields) []byte {
	var b strings.Builder
	b.WriteString(f.Command)
	if f.Args != "" {
		b.WriteByte(' ')
		b.WriteString(f.Args)
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// serializePOP3Resp 把 POP3 响应序列化为 TCP payload 字节,遵循 RFC 1939 §3:
//   - message 是状态行附带文本,可与多行正文(lines/eml)组合,也可单独(单行响应):
//     单行 = "status SP message\r\n"(无多行正文);
//     多行 = "status[ SP message]\r\n" + 正文 + <CRLF>.<CRLF> 终止符
//     (RFC 1939 §3 多行响应首行可带说明文本,如 LIST 的 "+OK 2 messages (320 octets)")。
//   - 多行正文(lines):各行 CRLF join → dotStuff → 追加 <CRLF>.<CRLF> 终止符。正文行做
//     RFC 1939 §3 dot-stuffing(行首 . → ..),与 eml_data 同一规则;status 行不参与 stuffing。
//   - 多行正文(eml):SerializeEMLData(eml) 取纯 RFC 5322 内容,由 POP3 接入层强制成帧
//     (dot-stuffing + <CRLF>.<CRLF> 终止符,与 lines 分支同一职责)。POP3 RETR/TOP 的
//     正文即 RFC 5322 邮件内容,成帧规则与 SMTP DATA 相同,由各自接入层强制。
//
// lines 与 eml 互斥(由校验保证);message 可与二者任一组合或单独使用。
func serializePOP3Resp(f *scenario.POP3ResponseFields) ([]byte, error) {
	var b bytes.Buffer
	// 1. status 行(不参与 dot-stuff):status[ SP message]\r\n。
	b.WriteString(f.Status)
	if f.Message != "" {
		b.WriteByte(' ')
		b.WriteString(f.Message)
	}
	b.WriteString("\r\n")

	// 单行响应(message 且无多行正文):status 行即整条响应。
	if len(f.Lines) == 0 && f.EML == nil {
		return b.Bytes(), nil
	}

	if len(f.Lines) > 0 {
		// 2. lines 多行:各行 CRLF join → dotStuff → 追加终止符 <CRLF>.<CRLF>。
		//    RFC 1939 §3:多行响应的正文行做 dot-stuffing(行首 . → ..),
		//    以 <CRLF>.<CRLF> 终止。逐行 join 后整段 stuffing 与 eml_data 一致。
		content := []byte(strings.Join(f.Lines, "\r\n"))
		b.Write(dotframe.AppendDotTerminator(dotframe.ApplyDotStuffing(content)))
		return b.Bytes(), nil
	}

	// 3. eml 多行:复用 SerializeEMLData 取纯 RFC 5322 内容,由 POP3 接入层强制成帧
	//    (dot-stuffing + <CRLF>.<CRLF> 终止符,RFC 1939 §3,无 opt-out;与 lines 分支
	//    同一成帧职责)。缺 dot-stuffing/缺终止符等畸形走 payload/payload_hex。
	eml, err := SerializeEMLData(f.EML)
	if err != nil {
		return nil, err
	}
	eml = dotframe.AppendDotTerminator(dotframe.ApplyDotStuffing(eml))
	b.Write(eml)
	return b.Bytes(), nil
}
