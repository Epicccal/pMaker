package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 POP3 命令 / 状态指示符的「合法基线」校验,对齐 smtp_request.go / ftp_command.go
// 的风格:已知命令接受(大小写不敏感),未知命令报错并引导改用 payload / payload_hex 原始字节
// 通道。
//
// 校验只判合法性,绝不改变序列化行为(序列化在 builder/pop3.go)。真正无法用结构化字段
// 表达的畸形(私有命令、非标状态指示符)走 payload / payload_hex 兜底。
//
// POP3 命令原样输出(不强制大写),保留 user/RETR/Retr 等大小写构造能力
// (RFC 1939 §3 命令大小写不敏感,是合规测试点)。

// knownPOP3Commands 是 POP3 已知命令表(RFC 1939 核心 + RFC 2449 CAPA + RFC 2595 STLS +
// RFC 1734/5034 AUTH),统一大写存储,匹配时大小写不敏感。私有命令不在表内,需走
// payload/payload_hex。
var knownPOP3Commands = map[string]struct{}{
	// RFC 1939 核心
	"USER": {}, "PASS": {}, "APOP": {}, "STAT": {}, "LIST": {},
	"RETR": {}, "DELE": {}, "NOOP": {}, "RSET": {}, "TOP": {},
	"UIDL": {}, "QUIT": {},
	// 扩展
	"CAPA": {}, // RFC 2449 能力协商
	"STLS": {}, // RFC 2595 TLS 升级
	"AUTH": {}, // RFC 1734/5034 SASL 认证
}

// pop3ArgsRule 是命令的 args 要求:required(必带)/ forbidden(禁带)/ optional(可选)。
// 只校验 args 的有/无,不校验 args 内容的合法性(避免过度约束畸形构造)。
// 文法依据见 RFC 1939 §8(RFC 1939 §6 的命令语法)+ RFC 2449 §3(CAPA)+ RFC 2595 §4(STLS)+ RFC 1734 §2(AUTH)。
var pop3ArgsRule = map[string]pop3ArgsPolicy{
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
	"CAPA": pop3ArgsForbidden,
	"STLS": pop3ArgsForbidden,
	"AUTH": pop3ArgsRequired, // SASL 机制
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
	if _, ok := knownPOP3Commands[uc]; !ok {
		return "", fmt.Errorf("未知 POP3 命令 %q(支持 RFC 1939 核心 USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT 与扩展 CAPA/STLS/AUTH;非标或私有命令请用 payload / payload_hex)", c)
	}
	return uc, nil
}

// validatePOP3RequestFields 校验 pop3_request 字段组合的合法性(command + args 约束)。
//   - command 经 validatePOP3Command 校验(已知表);
//   - args 有/无按 pop3ArgsRule 校验(required/forbidden/optional)。
//
// 只判合法性,不解析 args 内容(避免过度约束畸形构造)。
func validatePOP3RequestFields(f *POP3RequestFields) error {
	uc, err := validatePOP3Command(f.Command)
	if err != nil {
		return err
	}
	switch pop3ArgsRule[uc] {
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

// validatePOP3ResponseFields 校验 pop3_response 字段组合的合法性(status + message/lines/eml 约束)。
//   - status 非空且为 +OK / -ERR(大小写不敏感),否则报错引导 payload/payload_hex;
//   - message / lines / eml 三者互斥且至少其一非空(裸 status 行走 payload/payload_hex);
//   - eml 非空时委托 validateEMLDataFields 校验(复用既有 EML 校验)。
func validatePOP3ResponseFields(f *POP3ResponseFields) error {
	if f.Status == "" {
		return fmt.Errorf("需要 status(+OK / -ERR)")
	}
	us := strings.ToUpper(f.Status)
	if us != "+OK" && us != "-ERR" {
		return fmt.Errorf("status %q 非法,POP3 状态指示符只能是 +OK / -ERR(大小写不敏感;RFC 1939 §3);非标状态指示符请用 payload / payload_hex", f.Status)
	}
	// 互斥计数:eml 与 message/lines 不可同设。
	hasEML := f.EML != nil
	hasLines := len(f.Lines) > 0
	hasMsg := f.Message != ""
	// 三者互斥:任意两者同设即错。
	count := 0
	if hasMsg {
		count++
	}
	if hasLines {
		count++
	}
	if hasEML {
		count++
	}
	if count > 1 {
		return fmt.Errorf("message / lines / eml 只能配置一个")
	}
	if count == 0 {
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
