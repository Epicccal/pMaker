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

// serializeFTPResp 把 FTP 响应序列化为控制连接 payload 字节。
//
// 单行:message -> "code message\r\n"(message 为空则 "code\r\n")。
// 多行(RFC 959 §4.1.3 续行):lines 的每个元素一行,
//
//	"code-line1\r\n…\rcode-lineN-1\r\ncode lastline\r\n",
//
// 最后一行用空格前缀,其余用连字符前缀。空 lines 元素被跳过。
func serializeFTPResp(f *scenario.FTPResponseFields) []byte {
	var b strings.Builder
	if len(f.Lines) > 0 {
		// 跳过空元素,避免续行里出现空行(RFC 959 续行每行须以 code 前缀开头)。
		lines := make([]string, 0, len(f.Lines))
		for _, line := range f.Lines {
			if line != "" {
				lines = append(lines, line)
			}
		}
		for i, line := range lines {
			if i == len(lines)-1 {
				fmt.Fprintf(&b, "%d %s\r\n", f.Code, line)
			} else {
				fmt.Fprintf(&b, "%d-%s\r\n", f.Code, line)
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
