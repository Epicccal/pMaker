package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 POP3 命令 / 状态指示符的「合法基线」校验:已知命令接受(大小写不敏感),
// 未知命令报错并引导改用 payload / payload_hex 原始字节通道。
//
// 校验只判合法性,绝不改变序列化行为(序列化在 builder/pop3.go)。真正无法用结构化字段
// 表达的畸形(私有命令、非标状态指示符)走 payload / payload_hex 兜底。
//
// POP3 命令原样输出(不强制大写),保留 user/RETR/Retr 等大小写构造能力
// (RFC 1939 §3 命令大小写不敏感,是合规测试点)。

// pop3Commands 是 POP3 已知命令表(单源):键 = 大写命令名,值 = 该命令的 args 要求策略
// (required/forbidden/optional)。成员关系即「已知命令」,args 有/无按策略校验。
// 单表而非「已知表 + args 规则表」两张表:加命令只在此一处,不存在「加了一处忘了另一处、
// 新命令被 map 缺键零值静默当作某策略」的路径 —— map 字面量每键必须显式给值。
// 文法依据见 RFC 1939 §8(命令语法)+ RFC 2449 §3(CAPA)+ RFC 2595 §4(STLS)+ RFC 1734 §2(AUTH)。
var pop3Commands = map[string]pop3ArgsPolicy{
	// RFC 1939 核心
	"USER": pop3ArgsRequired, // 邮箱名
	"PASS": pop3ArgsRequired, // 密码
	"APOP": pop3ArgsRequired, // 邮箱名 + MD5 摘要
	"STAT": pop3ArgsForbidden,
	"LIST": pop3ArgsOptional, // 无参=多行;有参=msg#(单行)
	"RETR": pop3ArgsRequired, // msg#
	"DELE": pop3ArgsRequired, // msg#
	"NOOP": pop3ArgsForbidden,
	"RSET": pop3ArgsForbidden,
	"TOP":  pop3ArgsRequired, // "msg# n"
	"UIDL": pop3ArgsOptional, // 无参=多行;有参=msg#(单行)
	"QUIT": pop3ArgsForbidden,
	// 扩展
	"CAPA": pop3ArgsForbidden, // RFC 2449 能力协商
	"STLS": pop3ArgsForbidden, // RFC 2595 TLS 升级
	"AUTH": pop3ArgsRequired,  // RFC 1734/5034 SASL 认证机制
}

type pop3ArgsPolicy int

const (
	pop3ArgsRequired  pop3ArgsPolicy = iota // 必带 args
	pop3ArgsForbidden                       // 禁带 args
	pop3ArgsOptional                        // args 可有可无
)

// validatePOP3Command 校验 pop3_request.command:非空且属于已知命令表(大小写不敏感)。
// 未列入表的命令报错,并引导改用 payload / payload_hex 构造非标 / 私有命令。
// 返回大写化的 command(供后续字段约束分派用)。
func validatePOP3Command(c string) (string, error) {
	if c == "" {
		return "", fmt.Errorf("需要 command")
	}
	uc := strings.ToUpper(c)
	if _, ok := pop3Commands[uc]; !ok {
		return "", fmt.Errorf("未知 POP3 命令 %q(支持 RFC 1939 核心 USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT 与扩展 CAPA/STLS/AUTH;非标或私有命令请用 payload / payload_hex)", c)
	}
	return uc, nil
}

// validatePOP3RequestFields 校验 pop3_request 字段组合的合法性(command + args 约束)。
//   - command 经 validatePOP3Command 校验(已知表);
//   - args 有/无按 pop3Commands 中该命令的策略校验(required/forbidden/optional);
//   - args 不能含 \r 或 \n:POP3 以 CRLF 为命令行终止符,注入换行符会产出额外命令行;
//     需构造畸形命令行请用 payload / payload_hex。
//
// 只判合法性,不解析 args 内容(避免过度约束畸形构造)。
func validatePOP3RequestFields(f *POP3RequestFields) error {
	uc, err := validatePOP3Command(f.Command)
	if err != nil {
		return err
	}
	if hasCRLF(f.Args) {
		return fmt.Errorf("args 不能包含 \\r 或 \\n(会注入额外命令行;畸形 POP3 字节流请用 payload / payload_hex)")
	}
	switch pop3Commands[uc] {
	case pop3ArgsRequired:
		if f.Args == "" {
			return fmt.Errorf("%s 需要 args(如 RETR 需要 msg#)", f.Command)
		}
	case pop3ArgsForbidden:
		if f.Args != "" {
			return fmt.Errorf("%s 不接受参数(畸形请用 payload / payload_hex)", f.Command)
		}
	case pop3ArgsOptional:
		// 有/无均合规(LIST/UIDL)。
	}
	return nil
}

// validatePOP3Status 校验 pop3_response.status:非空,且为 +OK / -ERR / +(大小写不敏感)。
// +OK / -ERR 是 RFC 1939 §3 的标准状态指示符;+ 是 RFC 1734/4954 SASL 续行的服务器挑战
// (形如 "+ <base64>\r\n",单字符 + 而非 +OK),为 AUTH 流程的结构化构造能力纳入校验。
// 其余非标状态指示符报错,并引导改用 payload / payload_hex。
// 返回大写化的 status(供后续字段约束分派用)。
func validatePOP3Status(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("需要 status(+OK / -ERR / +)")
	}
	us := strings.ToUpper(s)
	switch us {
	case "+OK", "-ERR", "+":
		return us, nil
	default:
		return "", fmt.Errorf("status %q 非法,POP3 状态指示符只能是 +OK / -ERR / +(大小写不敏感;RFC 1939 §3,+ 为 RFC 1734/4954 SASL 续行);非标状态指示符请用 payload / payload_hex", s)
	}
}

// hasCRLF 报告字符串是否含 \r 或 \n。POP3 以 CRLF 为行终止符,结构化字段中注入换行符
// 会在字节流中产出额外命令 / 响应行,因此在校验阶段拦截;畸形 POP3 字节流请用 payload / payload_hex。
func hasCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// validatePOP3ResponseFields 校验 pop3_response 字段组合的合法性(status + message/lines/eml 约束)。
//   - status 非空且为 +OK / -ERR / +(大小写不敏感),否则报错引导 payload/payload_hex(+ 是
//     RFC 1734/4954 SASL 续行的服务器挑战,单字符 + 而非 +OK);
//   - 多行正文(lines/eml)仅 +OK 可用:RFC 1939 §3 多行响应均 +OK 起始(LIST/RETR/TOP/UIDL/CAPA);
//     -ERR 永远单行,+ 为单行 SASL 挑战,二者搭配 lines/eml 报错并引导走 payload/payload_hex;
//   - message 是状态行附带文本,可与 lines/eml 组合(RFC 1939 §3 多行响应首行可带说明文本,
//     如 LIST 的 "+OK 2 messages (320 octets)"、CAPA 的 "+OK Capability list follows"。
//     message 单独非空 = 单行响应;message 为空 = 裸 status 行 + 多行正文);
//   - lines 与 eml 互斥(多行正文二选一),二者同设报错;
//   - message/lines/eml 至少其一非空(裸 status 行走 payload/payload_hex);
//   - eml 非空时委托 validateEMLDataFields 校验(复用既有 EML 校验)。
func validatePOP3ResponseFields(f *POP3ResponseFields) error {
	us, err := validatePOP3Status(f.Status)
	if err != nil {
		return err
	}
	hasEML := f.EML != nil
	hasLines := len(f.Lines) > 0
	hasMsg := f.Message != ""
	// 多行正文仅 +OK 可用(RFC 1939 §3:LIST/RETR/TOP/UIDL/CAPA 等 +OK 响应才有多行);
	// -ERR 永远单行;RFC 1734/4954 SASL 续行 + 也是单行挑战。
	// -ERR/+ 搭配 lines/eml 属「非标状态指示符的用法」,引导走 payload/payload_hex 兜底。
	if us == "-ERR" && (hasLines || hasEML) {
		return fmt.Errorf("%s 永远单行(RFC 1939 §3),不接受多行正文;构造非标多行响应请用 payload / payload_hex", f.Status)
	}
	if us == "+" && (hasLines || hasEML) {
		return fmt.Errorf("%s 为 RFC 1734/4954 SASL 续行挑战,每轮挑战是独立单行(+ <base64>\\r\\n),不接受多行正文;多轮 AUTH 握手用多条独立 pop3_response,构造非标形态请用 payload / payload_hex", f.Status)
	}
	// message / lines 不能含 \r 或 \n:POP3 以 CRLF 为行终止符,注入换行符会产出额外响应行;
	// 畸形 POP3 字节流请用 payload / payload_hex。
	if hasCRLF(f.Message) {
		return fmt.Errorf("message 不能包含 \\r 或 \\n(会注入额外响应行;畸形 POP3 字节流请用 payload / payload_hex)")
	}
	for i, line := range f.Lines {
		if hasCRLF(line) {
			return fmt.Errorf("lines[%d] 不能包含 \\r 或 \\n(会注入额外响应行;畸形 POP3 字节流请用 payload / payload_hex)", i)
		}
	}
	// lines 与 eml 互斥(多行正文二选一);message 可与任一组合,也可单独(单行)。
	if hasLines && hasEML {
		return fmt.Errorf("lines 与 eml 互斥,只能配置一个多行正文")
	}
	// 至少 message/lines/eml 其一非空(裸 status 行走 payload/payload_hex)。
	if !hasMsg && !hasLines && !hasEML {
		return fmt.Errorf("需要 message / lines / eml(裸 status 行请用 payload / payload_hex)")
	}
	// eml 子结构校验委托。
	if hasEML {
		if err := validateEMLDataFields(f.EML); err != nil {
			return fmt.Errorf("eml: %w", err)
		}
	}
	return nil
}
