package builder

import (
	"bytes"
	"fmt"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeTelnet 把一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本)序列化为
// TCP payload 字节。gopacket 无 TELNET layer(见 telnet-implementation.md 关键技术约束),
// 故同 HTTP/FTP:自己序列化为原始字节,由 serializeStack 包裹成 gopacket.Payload。
//
// 一个 telnet 层 = 一个事件;层栈里重复多个 telnet 层由 SerializeLayers 顺序拼接,
// 自然得到 `IAC WILL ECHO IAC WILL SGA …` 连续字节(多事件同段)。
//
// IAC(0xFF)转义(RFC 854 §2):数据流中出现字面 0xFF 时必须输出 IAC IAC(0xFF 0xFF)。
// args 文本(可见 NVT 文本 / TTYPE 名)自动转义其中的 0xFF;args_hex 原始字节不转义
// (用于刻意构造畸形/非转义流量、NAWS 二进制)。
func serializeTelnet(f *scenario.TelnetFields) ([]byte, error) {
	// 纯 NVT 文本:command 留空,args 字节,其中 0xFF 自动转义为 IAC IAC。
	if f.Command == "" {
		return telnetEscape([]byte(f.Args)), nil
	}

	cmd, ok := scenario.TelnetCommandByte(f.Command)
	if !ok {
		return nil, fmt.Errorf("未知 command %q", f.Command)
	}

	// 二字节控制命令:IAC + cmd。
	if scenario.TelnetControlCommand(cmd) {
		return []byte{scenario.TelnetIAC, cmd}, nil
	}

	// 协商(WILL/WONT/DO/DONT):IAC + cmd + option(三字节)。
	opt, ok := scenario.TelnetOptionByte(f.Option)
	if !ok {
		return nil, fmt.Errorf("未知 option %q", f.Option)
	}
	if cmd != scenario.TelnetSB {
		return []byte{scenario.TelnetIAC, cmd, opt}, nil
	}

	// SB:IAC SB opt 内容 IAC SE。内容来源 args(自动转义)或 args_hex(原始字节)。
	var content []byte
	switch {
	case f.ArgsHex != "":
		b, err := scenario.ParsePayloadHex(f.ArgsHex)
		if err != nil {
			return nil, fmt.Errorf("args_hex: %w", err)
		}
		content = b
	case f.Args != "":
		// TTYPE 的 SB 内容约定(RFC 1091):IS(0x00)/SEND(0x01)限定符 + 终端名。
		// args 视作终端名,builder 自动前缀 IS 限定符(常见:服务器请求终端类型,
		// 客户端回 IS+名)。TTYPE SEND 需用户用 args_hex: "0x01" 显式表达(无终端名,
		// args 文本为空无法承载)。其它 option 的 SB 内容由 args/args_hex 完整给出
		// (含限定符),builder 不臆造。
		if opt == scenario.TelnetOptionTTYPE {
			content = append([]byte{scenario.TelnetTTypeIS}, telnetEscape([]byte(f.Args))...)
		} else {
			content = telnetEscape([]byte(f.Args))
		}
	default:
		return nil, fmt.Errorf("SB 须有 args 或 args_hex")
	}

	return bytes.Join([][]byte{
		{scenario.TelnetIAC, scenario.TelnetSB, opt},
		content,
		{scenario.TelnetIAC, scenario.TelnetSE},
	}, nil), nil
}

// telnetEscape 把数据中的字面 0xFF 转义为 IAC IAC(0xFF 0xFF),RFC 854 §2。
func telnetEscape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == scenario.TelnetIAC {
			out = append(out, scenario.TelnetIAC, scenario.TelnetIAC)
		} else {
			out = append(out, c)
		}
	}
	return out
}
