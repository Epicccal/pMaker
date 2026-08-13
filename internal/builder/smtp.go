package builder

import (
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeSMTPReq 把一条 SMTP 信封命令序列化为 TCP payload 字节。按 verb 身份分派
// (与校验一致):MAIL/RCPT 走结构化信封路径(from/to + params),builder 自动包 <>、
// 规范 FROM:/TO: 关键字(带冒号);其余 verb 走 args 普通参数路径(VERB args\r\n)。
// verb 原样输出(不强制大写),保留大小写构造能力(RFC 5321 §2.4 命令大小写不敏感)。
//
// 结构性畸形(缺 <>、非标空格、FROM/TO 关键字大小写非标、缺冒号)与私有/非标 verb
// 不经过本层(由校验拦截并引导 payload/payload_hex)。地址内容畸形(含 CRLF 注入)走结构化
// 路径即可:from/to 裸透传不转义,<> 框照常包裹。
func serializeSMTPReq(f *scenario.SMTPRequestFields) []byte {
	verb := strings.ToUpper(f.Verb)
	var b strings.Builder
	switch verb {
	case "MAIL", "RCPT":
		b.WriteString(f.Verb)
		b.WriteByte(' ')
		if verb == "MAIL" {
			b.WriteString("FROM:<")
			if f.From != nil {
				b.WriteString(*f.From)
			}
			b.WriteByte('>')
		} else {
			b.WriteString("TO:<")
			b.WriteString(f.To)
			b.WriteByte('>')
		}
		// esmtp-param(RFC 5321 §4.1.2: esmtp-keyword ["=" esmtp-value])按 YAML 声明顺序输出,
		// 空格分隔,接在路径后。空值 → 裸键(无值 flag,如 SMTPUTF8);非空 → KEY=VALUE。
		// 保留声明顺序、支持重复键(如多个 ORCPT);nil/空 HeaderMap 安全(Range 不迭代)。
		if f.Params.Len() > 0 {
			f.Params.Range(func(k, v string) {
				b.WriteByte(' ')
				b.WriteString(k)
				if v != "" {
					b.WriteByte('=')
					b.WriteString(v)
				}
			})
		}
		b.WriteString("\r\n")
	default:
		// args 普通参数路径:VERB args\r\n(args 空则裸 VERB\r\n,如 DATA/QUIT/STARTTLS)。
		// args 为空不追加空格,非空前缀单空格。行尾统一 CRLF。
		b.WriteString(f.Verb)
		if f.Args != "" {
			b.WriteByte(' ')
			b.WriteString(f.Args)
		}
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// serializeSMTPResp 把 SMTP 响应序列化为 TCP payload 字节,遵循 RFC 5321 §4.2 的 Reply-line 文法:
//   - 续行(非末行)"code-[text]\r\n" —— 每条续行都带 code- 前缀(textstring 可选,故续行空文本 "code-\r\n" 合法);
//   - 末行 "code[ SP text]\r\n" —— SP 与 textstring 一起可选:末行无文本时纯 "code\r\n"(无尾随空格)才严格合规。
//
// message 与 lines 互斥:lines 非空走多行;否则走单行(message 为空则裸 "code\r\n")。
// 空文本行如实输出不丢弃(续行空文本 RFC 5321 合规)。
func serializeSMTPResp(f *scenario.SMTPResponseFields) []byte {
	var b strings.Builder
	if len(f.Lines) > 0 {
		for i, line := range f.Lines {
			if i == len(f.Lines)-1 {
				// 末行:code[ SP text]。空文本 → 纯 code(无尾随空格),严格 RFC 5321。
				if line == "" {
					fmt.Fprintf(&b, "%d\r\n", f.Code)
				} else {
					fmt.Fprintf(&b, "%d %s\r\n", f.Code, line)
				}
			} else {
				// 续行:code-[text](textstring 可选)。
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
