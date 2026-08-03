package builder

import (
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeFTPReq 把 FTP 命令序列化为控制连接 payload 字节:COMMAND[ arg]\r\n。
// command 原样输出(不强制大写),以便构造小写/非标命令等畸形用例;
// args 为空时不追加空格。行尾统一 CRLF(RFC 959)。
func serializeFTPReq(f *scenario.FTPRequestFields) []byte {
	var b strings.Builder
	b.WriteString(f.Command)
	if f.Args != "" {
		b.WriteByte(' ')
		b.WriteString(f.Args)
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// serializeFTPResp 把 FTP 响应序列化为控制连接 payload 字节,委托给共用的
// serializeTextReply。多行续行格式见 RFC 959 §4.1.3。
func serializeFTPResp(f *scenario.FTPResponseFields) []byte {
	return serializeTextReply(f.Code, f.Message, f.Lines)
}
