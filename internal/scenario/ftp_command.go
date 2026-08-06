package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 FTP 控制连接命令名 / 响应码的「合法基线」校验:已知命令名接受
// (大小写不敏感),未知命令名报错并引导改用 payload / payload_hex 原始字节通道。
//
// 背景:此前 ftp_request.command 接受任意字符串(含空格、空),ftp_response.code 接受任意
// int(如 code: 22 会序列化成 "22\r\n",非法但无提示)。合法用例的拼写错误(如 RETER)会
// 静默通过,只有有意畸形才靠"不强制大写"兜底,缺少合法基线校验。本文件补上这道基线:
//   - command:必须在已知命令表内(RFC 959 + 常见扩展),大小写不敏感;未列入则报错,
//     引导用 payload/payload_hex 自行构造非标 / 私有命令(畸形通道)。
//   - code:必须是三位 FTP 响应码(100-599,首位 1-5),覆盖 RFC 959 全部响应类
//     (1xx 信息 / 2xx 成功 / 3xx 中间 / 4xx 暂时失败 / 5xx 永久失败);不强制必须是
//     RFC 已定义码,保留扩展空间,但拦截 code: 22 / 负数 / >999 等非法位数。
//
// command 仍原样输出(不强制大写),以便构造小写 / 非标命令等畸形用例 —— 校验只判合法性,
// 不改变序列化行为。真正无法用结构化字段表达的畸形(自定义动词、CRLF 注入等)走
// payload / payload_hex 原始字节兜底。

// knownFTPCommands 是 FTP 控制连接已知命令表(RFC 959 核心 + 常见扩展),统一大写存储,
// 匹配时大小写不敏感。扩展命令收录业界普遍实现(FEAT/OPTS/AUTH TLS/PBSZ/PROT/MLSD/MLST/
// MDTM/SIZE/HOST/CLNT/MFMT/CCC),站点私有命令不在表内,需走 payload/payload_hex。
var knownFTPCommands = map[string]struct{}{
	// RFC 959 核心
	"USER": {}, "PASS": {}, "ACCT": {}, "CWD": {}, "CDUP": {}, "SMNT": {},
	"QUIT": {}, "REIN": {}, "PORT": {}, "PASV": {}, "TYPE": {}, "STRU": {},
	"MODE": {}, "RETR": {}, "STOR": {}, "STOU": {}, "APPE": {}, "ALLO": {},
	"REST": {}, "RNFR": {}, "RNTO": {}, "ABOR": {}, "DELE": {}, "RMD": {},
	"MKD": {}, "PWD": {}, "LIST": {}, "NLST": {}, "SITE": {}, "SYST": {},
	"STAT": {}, "HELP": {}, "NOOP": {},
	// 常见扩展(RFC 959 之外,解析端普遍识别)
	"FEAT": {}, "OPTS": {}, "AUTH": {}, "PBSZ": {}, "PROT": {},
	"MLSD": {}, "MLST": {}, "MDTM": {}, "SIZE": {}, "HOST": {},
	"CLNT": {}, "MFMT": {}, "CCC": {}, "EPRT": {}, "EPSV": {},
}

// validateFTPCommand 校验 ftp_request.command:非空且属于已知命令表(大小写不敏感)。
// 未列入表的命令报错,并引导改用 payload / payload_hex 构造非标 / 私有命令。
func validateFTPCommand(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("需要 command")
	}
	if _, ok := knownFTPCommands[strings.ToUpper(cmd)]; ok {
		return nil
	}
	return fmt.Errorf("未知 FTP 命令 %q(支持 RFC 959 核心与常见扩展如 USER/RETR/PASV/FEAT/AUTH;非标或私有命令请用 payload / payload_hex)", cmd)
}

// validateFTPResponseCode 校验 ftp_response.code:三位 FTP 响应码 100-599(首位 1-5)。
// 覆盖 RFC 959 全部响应类,不强制必须是 RFC 已定义码(保留扩展),但拦截非法位数与负数。
func validateFTPResponseCode(code int) error {
	if code < 100 || code > 599 {
		return fmt.Errorf("code %d 非法,FTP 响应码须为三位 100-599(首位 1-5);非标响应码请用 payload / payload_hex", code)
	}
	return nil
}
