package builder

import (
	"sort"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeSMTPReq 把一条 SMTP 信封命令序列化为 TCP payload 字节。按 verb 身份分派
// (与校验一致):MAIL/RCPT 走结构化信封路径(from/to + params),builder 自动包 <>、
// 规范 FROM:/TO: 关键字(带冒号);其余 verb 走 args 普通参数路径(VERB args\r\n)。
// verb 原样输出(不强制大写),保留大小写构造能力(RFC 5321 §2.4 命令大小写不敏感)。
//
// 结构性畸形(缺 <>、非标空格、FROM/TO 关键字大小写非标、缺冒号)与私有/非标 verb
// 不经过本层(由校验拦截并引导 payload/payload_hex),与全项目「非标走原始字节兜底」一致。
// 地址内容畸形(含 CRLF 注入)走结构化路径即可:from/to 裸透传不转义,<> 框照常包裹。
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
		// esmtp-param(RFC 5321 §4.1.2: esmtp-keyword ["=" esmtp-value])按 key 字典序升序输出,
		// 空格分隔,接在路径后。空值 → 裸键(无值 flag,如 SMTPUTF8);非空 → KEY=VALUE。
		// 排序保证确定性输出(复用项目 HTTP 头按 key 排序先例);nil map 排序循环安全。
		if len(f.Params) > 0 {
			keys := make([]string, 0, len(f.Params))
			for k := range f.Params {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				b.WriteByte(' ')
				b.WriteString(k)
				if v := f.Params[k]; v != "" {
					b.WriteByte('=')
					b.WriteString(v)
				}
			}
		}
		b.WriteString("\r\n")
	default:
		// args 普通参数路径:VERB args\r\n(args 空则裸 VERB\r\n,如 DATA/QUIT/STARTTLS)。
		// 与 serializeFTPReq 同构:args 为空不追加空格,非空前缀单空格。行尾统一 CRLF。
		b.WriteString(f.Verb)
		if f.Args != "" {
			b.WriteByte(' ')
			b.WriteString(f.Args)
		}
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// serializeSMTPResp 把 SMTP 响应序列化为 TCP payload 字节,委托给共用的 serializeTextReply。
// 多行续行格式遵循 RFC 5321 §4.2 的 Reply-line(每条续行带 code- 前缀,末行 code[ SP textstring]),
// 该公共函数逐行带 code- 的实现恰好匹配 RFC 5321 文法(复用依据是 SMTP 自身文法,非"与 FTP 相同")。
func serializeSMTPResp(f *scenario.SMTPResponseFields) []byte {
	return serializeTextReply(f.Code, f.Message, f.Lines)
}
