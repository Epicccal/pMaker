package scenario

import (
	"fmt"
	"strconv"
	"strings"
)

// 本文件实现 TELNET 命令码 / option 码的「合法基线」校验与名字↔字节翻译,对齐 DNS 枚举与
// FTP 命令的校验风格:已知名字接受(大小写不敏感),未知名字尝试十进制/0x 数字回退
// (私有/未列入码),既非已知名又非法数字则报错并引导改用 payload / payload_hex 原始字节通道。
//
// 与 ftp_command.go 同理:校验只判合法性,不改变序列化行为(序列化在 builder/telnet.go,
// 通过 TelnetCommandByte / TelnetOptionByte 取字节码)。真正无法用结构化字段表达的畸形
// (非法 IAC 序列、未转义 0xFF 等)走 payload / payload_hex,与全项目「非标值走原始字节兜底」
// 的约定一致。
//
// TELNET 字节常量见 RFC 854(IAC/命令)与各 option RFC;此处按数值集中登记。

// TELNET 协议字节常量(RFC 854 / RFC 1091),导出供 builder 构包时直接拼字节,
// 与 HTTP/FTP 在 builder 内构包的模式一致:scenario 定义单一常量来源,builder 引用。
const (
	TelnetIAC  = 0xFF // Interpret As Command(RFC 854)
	telnetDONT = 0xFE
	telnetDO   = 0xFD
	telnetWONT = 0xFC
	telnetWILL = 0xFB
	TelnetSB   = 0xFA // Subnegotiation Begin
	telnetGA   = 0xF9 // Go Ahead
	telnetEL   = 0xF8 // Erase Line
	telnetEC   = 0xF7 // Erase Character
	telnetAYT  = 0xF6 // Are You There
	telnetAO   = 0xF5 // Abort Output
	telnetIP   = 0xF4 // Interrupt Process
	telnetBRK  = 0xF3 // Break
	telnetDM   = 0xF2 // Data Mark
	telnetNOP  = 0xF1 // No Operation
	TelnetSE   = 0xF0 // Subnegotiation End
	telnetEOR  = 0xEF // End of Record(RFC 885)

	// TelnetOptionTTYPE = TERMINAL-TYPE option 码(RFC 1091)。
	TelnetOptionTTYPE = 24
	// TTYPE subnegotiation 限定符(RFC 1091):IS=0,SEND=1。
	TelnetTTypeIS   = 0x00
	TelnetTTypeSEND = 0x01
)

// knownTelnetCommands 是 TELNET 已知命令表(统一大写存储,匹配大小写不敏感)→ IAC 命令字节。
// 含 RFC 854 二字节控制命令与协商动词 WILL/WONT/DO/DONT/SB。
var knownTelnetCommands = map[string]byte{
	"WILL": telnetWILL,
	"WONT": telnetWONT,
	"DO":   telnetDO,
	"DONT": telnetDONT,
	"SB":   TelnetSB,
	"GA":   telnetGA,
	"EL":   telnetEL,
	"EC":   telnetEC,
	"AYT":  telnetAYT,
	"AO":   telnetAO,
	"IP":   telnetIP,
	"BRK":  telnetBRK,
	"DM":   telnetDM,
	"NOP":  telnetNOP,
	"EOR":  telnetEOR,
}

// knownTelnetOptions 是 TELNET 已知 option 表(统一大写存储,匹配大小写不敏感)→ option 字节。
// 涵盖 RFC 856/857/858/859/860/885/1091/1073/1116/1184/1572 等常见 option。
var knownTelnetOptions = map[string]byte{
	"BINARY":      0,  // TRANSMIT-BINARY(RFC 856)
	"ECHO":        1,  // RFC 857
	"SGA":         3,  // Suppress Go Ahead(RFC 858)
	"STATUS":      5,  // RFC 859
	"TM":          6,  // TIMING-MARK(RFC 860)
	"EOR":         25, // End of Record(RFC 885)
	"TTYPE":       24, // TERMINAL-TYPE(RFC 1091)
	"NAWS":        31, // Negotiate About Window Size(RFC 1073)
	"TSPEED":      8,  // Terminal Speed(RFC 1079)
	"LINEMODE":    34, // RFC 1184
	"OLD_ENVIRON": 36, // RFC 1408(旧)
	"NEW_ENVIRON": 39, // RFC 1572
}

// telnetControlCommands 是「二字节控制命令」集合(仅 IAC + cmd,无 option):
// GA/EL/EC/AYT/AO/IP/BRK/DM/NOP/EOR。用于校验时区分控制命令(禁带 option/args)
// 与协商/SB(必带 option)。以命令字节为键便于按 parseTelnetCommand 结果查询。
var telnetControlCommands = map[byte]bool{
	telnetGA:  true,
	telnetEL:  true,
	telnetEC:  true,
	telnetAYT: true,
	telnetAO:  true,
	telnetIP:  true,
	telnetBRK: true,
	telnetDM:  true,
	telnetNOP: true,
	telnetEOR: true,
}

// TelnetControlCommand 判断一个命令字节是否为「二字节控制命令」
// (仅 IAC + cmd,无 option):GA/EL/EC/AYT/AO/IP/BRK/DM/NOP/EOR。
// 供 builder 序列化时区分控制命令与协商/SB。校验阶段也用它。
func TelnetControlCommand(cmd byte) bool {
	return telnetControlCommands[cmd]
}

// TelnetCommandByte 把命令名/数字翻译为 IAC 命令字节。校验已通过的 command 一定能解析;
// 返回 ok=false 表示未知(校验阶段会先拦截,此处供 builder 用)。
func TelnetCommandByte(s string) (byte, bool) {
	if v, ok := knownTelnetCommands[strings.ToUpper(s)]; ok {
		return v, true
	}
	n, err := parseTelnetByte(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// TelnetOptionByte 把 option 名/数字翻译为 option 字节。
func TelnetOptionByte(s string) (byte, bool) {
	if v, ok := knownTelnetOptions[strings.ToUpper(s)]; ok {
		return v, true
	}
	n, err := parseTelnetByte(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseTelnetByte 把字符串当单字节解析:十进制或 0x 十六进制。用于命令/option 的数字写法
// (私有/未列入码模糊测试)。对齐 builder.parseDNSRRNumber 风格,但限单字节(0..255)。
func parseTelnetByte(s string) (byte, error) {
	t := strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		t = t[2:]
		base = 16
	}
	n, err := strconv.ParseUint(t, base, 16)
	if err != nil {
		return 0, fmt.Errorf("非数字 %q", s)
	}
	if n > 0xff {
		return 0, fmt.Errorf("%q 超出单字节范围(0..255)", s)
	}
	return byte(n), nil
}

// parseTelnetCommand 与 parseTelnetOption 是校验用版本:解析失败返回带引导的 error
// (引导改用 payload / payload_hex),供 validateTelnetFields 直接使用。
func parseTelnetCommand(s string) (byte, error) {
	if v, ok := knownTelnetCommands[strings.ToUpper(s)]; ok {
		return v, nil
	}
	n, err := parseTelnetByte(s)
	if err != nil {
		return 0, fmt.Errorf("未知 TELNET 命令 %q(支持 WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR;非标命令请用 payload / payload_hex)", s)
	}
	return n, nil
}

func parseTelnetOption(s string) (byte, error) {
	if v, ok := knownTelnetOptions[strings.ToUpper(s)]; ok {
		return v, nil
	}
	n, err := parseTelnetByte(s)
	if err != nil {
		return 0, fmt.Errorf("未知 TELNET option %q(支持 ECHO/SGA/TTYPE/NAWS/BINARY/STATUS/TM/…;私有码用数字如 200,非标内容请用 payload / payload_hex)", s)
	}
	return n, nil
}

// validateTelnetFields 校验一个 telnet 层字段组合的合法性:
//   - command:在已知命令表内(大小写不敏感)或合法数字;空 command 合法(= 纯 NVT 文本)。
//   - WILL/WONT/DO/DONT/SB 必须带 option;二字节控制命令(GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR)
//     禁止带 option / args / args_hex。
//   - option:已知名或合法数字。
//   - args 与 args_hex 互斥(至多其一);args_hex 用 ParsePayloadHex 校验。
//   - 纯文本(command 空)须有 args(空文本无意义);SB 须有 args 或 args_hex 之一作 subneg 内容。
func validateTelnetFields(f *TelnetFields) error {
	// args 与 args_hex 互斥。
	if f.Args != "" && f.ArgsHex != "" {
		return fmt.Errorf("args 与 args_hex 只能配置一个")
	}
	if f.ArgsHex != "" {
		if _, err := ParsePayloadHex(f.ArgsHex); err != nil {
			return fmt.Errorf("args_hex: %w", err)
		}
	}

	// 纯 NVT 文本:command 留空,须有 args。
	if f.Command == "" {
		if f.Args == "" && f.ArgsHex == "" {
			return fmt.Errorf("纯文本(command 留空)须有 args 或 args_hex")
		}
		if f.Option != "" {
			return fmt.Errorf("纯文本(command 留空)不可带 option")
		}
		return nil
	}

	cmd, err := parseTelnetCommand(f.Command)
	if err != nil {
		return err
	}

	// 二字节控制命令:禁止带 option / args / args_hex。
	if telnetControlCommands[cmd] {
		if f.Option != "" {
			return fmt.Errorf("控制命令 %q 不带 option", f.Command)
		}
		if f.Args != "" || f.ArgsHex != "" {
			return fmt.Errorf("控制命令 %q 不带 args / args_hex", f.Command)
		}
		return nil
	}

	// 协商(WILL/WONT/DO/DONT)与 SB:必须带 option。
	if f.Option == "" {
		return fmt.Errorf("%s 必须带 option", f.Command)
	}
	if _, err := parseTelnetOption(f.Option); err != nil {
		return err
	}

	// SB:须有 args 或 args_hex 之一作 subneg 内容(IAC SB opt 内容 IAC SE,
	// 内容为空无意义)。
	if cmd == TelnetSB {
		if f.Args == "" && f.ArgsHex == "" {
			return fmt.Errorf("SB 须有 args 或 args_hex 之一作 subneg 内容")
		}
	}

	// 协商(WILL/WONT/DO/DONT)通常不带 args/args_hex;若给出则报错(三字节命令无内容位)。
	if cmd != TelnetSB && (f.Args != "" || f.ArgsHex != "") {
		return fmt.Errorf("%q 协商命令不带 args / args_hex", f.Command)
	}
	return nil
}
