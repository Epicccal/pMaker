package builder

import (
	"fmt"
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

// serializeFTPResp 把 FTP 响应序列化为控制连接 payload 字节。多行续行格式见 RFC 959 §4.2:
//   - 首行 "code-text\r\n"(code 后紧跟连字符,再接文本);
//   - 中间行是裸文本(无 code 前缀),如实输出;
//   - 末行 "code[ SP text]\r\n"(code 后紧跟空格,文本可选)。
//
// 空文本行协议合法(RFC 959 末行 "optionally some text"),如实输出不丢弃:
// 末行空文本 → "code \r\n"(code + 空格,无文本)。
//
// message 与 lines 互斥:lines 非空走多行;否则走单行(message 为空则裸 "code\r\n")。
func serializeFTPResp(f *scenario.FTPResponseFields) []byte {
	var b strings.Builder
	if len(f.Lines) > 0 {
		for i, line := range f.Lines {
			switch i {
			case 0:
				// 首行:code- text
				fmt.Fprintf(&b, "%d-%s\r\n", f.Code, line)
			case len(f.Lines) - 1:
				// 末行:code [SP text]
				fmt.Fprintf(&b, "%d %s\r\n", f.Code, line)
			default:
				// 中间行:裸文本(无 code 前缀)
				fmt.Fprintf(&b, "%s\r\n", line)
			}
		}
		return []byte(b.String())
	}
	if f.Message == "" {
		fmt.Fprintf(&b, "%d\r\n", f.Code)
	} else {
		fmt.Fprintf(&b, "%d %s\r\n", f.Code, f.Message)
	}
	return []byte(b.String())
}
