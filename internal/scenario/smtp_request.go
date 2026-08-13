package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 SMTP 信封命令 verb / 响应码的「合法基线」校验:已知 verb 接受
// (大小写不敏感),未知 verb 报错并引导改用 payload / payload_hex 原始字节通道。
//
// 校验只判合法性,绝不改变序列化行为(序列化在 builder/smtp.go)。真正无法用结构化字段
// 表达的畸形(私有 verb、MAIL/RCPT 结构性畸形如缺 <>、非标空格、FROM/TO 大小写非标、
// 缺冒号)走 payload / payload_hex 原始字节兜底。
//
// SMTP verb 原样输出(不强制大写),保留 helo/MAIL/Mail 等大小写构造能力
// (RFC 5321 §2.4 命令大小写不敏感,是合规测试点);结构化路径只规范 FROM/TO 关键字与 <> 包裹。

// knownSMTPVerbs 是 SMTP 已知 verb 表(RFC 5321 核心 + RFC 821 历史 + 常见扩展),
// 统一大写存储,匹配时大小写不敏感。私有 verb 不在表内,需走 payload/payload_hex。
var knownSMTPVerbs = map[string]struct{}{
	// RFC 5321 核心
	"HELO": {}, "EHLO": {}, "MAIL": {}, "RCPT": {}, "DATA": {},
	"RSET": {}, "VRFY": {}, "EXPN": {}, "HELP": {}, "NOOP": {}, "QUIT": {},
	// RFC 821 历史(deprecated 但保留以构造兼容/遗留流量)
	"TURN": {}, "SEND": {}, "SOML": {}, "SAML": {},
	// 常见扩展 verb
	"AUTH":     {}, // RFC 4954
	"STARTTLS": {}, // RFC 3207
	"BDAT":     {}, // RFC 3030 CHUNKING
	"ETRN":     {}, // RFC 1985
	"ATRN":     {}, // RFC 2645 ODMR
}

// smtpArgsRule 是 verb 的 args 要求:required(必带)/ forbidden(禁带)/ optional(可选)。
// 只校验 args 的有/无,不校验 args 内容的合法性(args 内容校验留后续语义级阶段)。
// 文法依据见 §4「verb 参数要求」表(RFC 5321 §4.1 / RFC 4954 / RFC 3030 / RFC 1985 / RFC 2645)。
var smtpArgsRule = map[string]smtpArgsPolicy{
	"EHLO":     smtpArgsRequired,
	"HELO":     smtpArgsRequired,
	"MAIL":     smtpArgsStruct, // 走结构化 from/to+params,不在此判 args
	"RCPT":     smtpArgsStruct,
	"DATA":     smtpArgsForbidden,
	"RSET":     smtpArgsForbidden,
	"QUIT":     smtpArgsForbidden,
	"STARTTLS": smtpArgsForbidden,
	"VRFY":     smtpArgsRequired,
	"EXPN":     smtpArgsRequired,
	"HELP":     smtpArgsOptional,
	"NOOP":     smtpArgsOptional,
	"AUTH":     smtpArgsRequired,
	"BDAT":     smtpArgsRequired,
	"ETRN":     smtpArgsRequired,
	"ATRN":     smtpArgsOptional,
	"TURN":     smtpArgsForbidden,
	"SEND":     smtpArgsRequired,
	"SOML":     smtpArgsRequired,
	"SAML":     smtpArgsRequired,
}

type smtpArgsPolicy int

const (
	smtpArgsRequired  smtpArgsPolicy = iota // 必带 args
	smtpArgsForbidden                       // 禁带 args
	smtpArgsOptional                        // args 可有可无
	smtpArgsStruct                          // MAIL/RCPT 走结构化路径,args 由信封字段校验单独处理
)

// validateSMTPVerb 校验 smtp_request.verb:非空且属于已知 verb 表(大小写不敏感)。
// 未列入表的 verb 报错,并引导改用 payload / payload_hex 构造非标 / 私有 verb。
// 返回大写化的 verb(供后续字段约束分派用),便于上层统一查表。
func validateSMTPVerb(v string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("需要 verb")
	}
	uv := strings.ToUpper(v)
	if _, ok := knownSMTPVerbs[uv]; !ok {
		return "", fmt.Errorf("未知 SMTP verb %q(支持 RFC 5321 核心 HELO/EHLO/MAIL/RCPT/DATA/…与常见扩展 AUTH/STARTTLS/BDAT 等;非标或私有 verb 请用 payload / payload_hex)", v)
	}
	return uv, nil
}

// validateSMTPResponseCode 校验 smtp_response.code:RFC 5321 §4.2 Reply-code =
// %x32-35 %x30-35 %x30-39,即三位十进制:百位 ∈ {2,3,4,5}、十位 ∈ {0..5}、
// 个位 ∈ {0..9}(SMTP 无 1xx)。注意不能只判 200-559 区间:260-299/360-399/460-499
// 的十位为 6-9,虽落在 200-559 区间内但按文法非法,需逐位校验。
// 不强制必须是 RFC 已定义码(保留扩展),但拦截非法位数与十位越界;非标响应码请用 payload / payload_hex。
//
// 错误信息按越界种类分支给出对症提示,而非对任何非法码都笼统说"须为三位":
//   - 非三位(负数 / 1-2 位 / 四位以上):明示"必须是三位";
//   - 百位越界(1xx / 6xx-9xx):明示"百位须 2-5"(SMTP 无 1xx);
//   - 十位越界(260-299 / 360-399 / 460-499):明示"十位须 0-5"(这是区间内逐位才拦得到的那类)。
func validateSMTPResponseCode(code int) error {
	if code < 100 || code > 999 {
		return fmt.Errorf("code %d 非法,SMTP 响应码必须是三位(RFC 5321 §4.2);非标响应码请用 payload / payload_hex", code)
	}
	d1, d2 := code/100, (code/10)%10
	switch {
	case d1 < 2 || d1 > 5:
		return fmt.Errorf("code %d 非法,SMTP 响应码百位须 2-5(SMTP 无 1xx;RFC 5321 §4.2);非标响应码请用 payload / payload_hex", code)
	case d2 > 5:
		return fmt.Errorf("code %d 非法,SMTP 响应码十位须 0-5(RFC 5321 §4.2 逐位文法;260-299/360-399 等虽落在 200-559 区间但十位越界);非标响应码请用 payload / payload_hex", code)
	}
	return nil
}

// validateSMTPRequestFields 校验 smtp_request 字段组合的合法性(verb + 信封字段约束)。
// 分派基准是 verb 身份(与序列化一致):MAIL/RCPT = 结构化信封路径;其余 verb = args 普通参数路径。
//
//   - MAIL/RCPT(结构化路径):MAIL 须配 from(指针三态:nil 报错/""→<>/"addr"→<addr>),禁 to/args;
//     RCPT 须配 to(非空),禁 from/args;params 可选。
//   - 非 MAIL/RCPT verb(args 普通参数路径):禁 from/to;params 仅对 MAIL/RCPT 有效(给非 MAIL/RCPT 报错);
//     args 按 verbArgsRule 校验有/无(required/forbidden/optional)。
//
// 只判合法性,不解析 args / params 内容(避免过度约束畸形构造;内容语义校验属后续阶段)。
func validateSMTPRequestFields(f *SMTPRequestFields) error {
	uv, err := validateSMTPVerb(f.Verb)
	if err != nil {
		return err
	}

	switch uv {
	case "MAIL", "RCPT":
		// 结构化信封路径:禁 args。
		if f.Args != "" {
			return fmt.Errorf("%s 不支持 args(MAIL/RCPT 走 from/to + params 结构化路径;结构性畸形请用 payload / payload_hex)", f.Verb)
		}
		// params 仅对 MAIL/RCPT 有效,此处允许。
		if uv == "MAIL" {
			if f.From == nil {
				return fmt.Errorf("%s 需要 from(退信 null reverse path 请显式写 from: \"\")", f.Verb)
			}
			if f.To != "" {
				return fmt.Errorf("%s 不支持 to", f.Verb)
			}
		} else { // RCPT
			if f.To == "" {
				return fmt.Errorf("%s 需要 to(前向路径不可为空;空路径畸形请用 payload / payload_hex)", f.Verb)
			}
			if f.From != nil {
				return fmt.Errorf("%s 不支持 from", f.Verb)
			}
		}
		return nil
	default:
		// args 普通参数路径:禁 from/to/params。
		if f.From != nil {
			return fmt.Errorf("verb %s 不支持 from(from 仅对 MAIL 有效)", f.Verb)
		}
		if f.To != "" {
			return fmt.Errorf("verb %s 不支持 to(to 仅对 RCPT 有效)", f.Verb)
		}
		if f.Params.Len() > 0 {
			return fmt.Errorf("params 仅对 MAIL/RCPT 有效")
		}
		// args 有/无按 verbArgsRule 校验。
		switch smtpArgsRule[uv] {
		case smtpArgsRequired:
			if f.Args == "" {
				return fmt.Errorf("%s 需要 args(如 EHLO 需要域名)", f.Verb)
			}
		case smtpArgsForbidden:
			if f.Args != "" {
				return fmt.Errorf("%s 不接受参数(畸形请用 payload / payload_hex)", f.Verb)
			}
		case smtpArgsOptional:
			// 有/无均合规(NOOP/HELP/ATRN)。
		}
		return nil
	}
}

// validateSMTPResponseFields 校验 smtp_response 字段组合的合法性(code + message/lines 约束)。
// 把响应侧的字段约束收敛进一处。
//
//   - code 经 validateSMTPResponseCode 校验(200-559);
//   - message 与 lines 互斥(至多其一),且至少一个非空(响应须有正文,裸 code 请走 payload/payload_hex)。
func validateSMTPResponseFields(f *SMTPResponseFields) error {
	if err := validateSMTPResponseCode(f.Code); err != nil {
		return err
	}
	if f.Message != "" && len(f.Lines) > 0 {
		return fmt.Errorf("message 与 lines 只能配置一个")
	}
	if f.Message == "" && len(f.Lines) == 0 {
		return fmt.Errorf("需要 message 或 lines(裸 code 请用 payload / payload_hex)")
	}
	return nil
}
