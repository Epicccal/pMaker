package builder

import (
	"bytes"
	"fmt"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeTelnet 把一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本)序列化为
// TCP payload 字节。gopacket 无 TELNET layer,故自己序列化为原始字节,
// 由 serializeStack 包裹成 gopacket.Payload。
//
// 一个 telnet 层 = 一个事件;层栈里重复多个 telnet 层由 SerializeLayers 顺序拼接,
// 自然得到 `IAC WILL ECHO IAC WILL SGA …` 连续字节(多事件同段)。
//
// 转义/归一规则(RFC 854 §2,只作用于 NVT 文本流,即 command 留空的 args;
// SB subnegotiation 内容是 option 专有二进制,仅做 IAC 转义用于定位 SE,不套 CR NUL):
//   - IAC(0xFF):字面 0xFF 输出为 IAC IAC(0xFF 0xFF)。
//   - CR(0x0D):后随 LF(0x0A)的行结束序列原样保留;裸 CR(后非 LF)按 RFC 854 §2
//     编码为 CR NUL(0x0D 0x00),表示"回车不换行",避免与行结束歧义。
//   - args_hex 原始字节不转义/不归一(用于刻意构造畸形/非转义流量、NAWS 二进制)。
func serializeTelnet(f *scenario.TelnetFields) ([]byte, error) {
	// 纯 NVT 文本:command 留空,args(文本,IAC 转义 + 裸 CR 归一为 CR NUL)或
	// args_hex(原始字节,不转义/不归一)。
	// 二者在校验阶段已保证互斥且至少其一(args_hex 用于注入含二进制/0xFF 的 NVT 文本)。
	if f.Command == "" {
		if f.ArgsHex != "" {
			b, err := scenario.ParsePayloadHex(f.ArgsHex)
			if err != nil {
				return nil, fmt.Errorf("args_hex: %w", err)
			}
			return b, nil
		}
		return telnetNVTData([]byte(f.Args)), nil
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

	// SB:IAC SB opt 内容 IAC SE。内容来源 args(仅 IAC 转义)或 args_hex(原始字节)。
	// SB 内容是 option 专有二进制(如 TTYPE 名、NAWS),不套 NVT 的 CR NUL 归一。
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
			content = append([]byte{scenario.TelnetTTypeIS}, telnetEscapeBytes([]byte(f.Args))...)
		} else {
			content = telnetEscapeBytes([]byte(f.Args))
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

// telnetNVTData 对 NVT 文本流做 RFC 854 §2 转义与归一:
//   - IAC(0xFF)转义为 IAC IAC;
//   - 裸 CR(CR 后不随 LF)归一为 CR NUL,表示"回车不换行",避免与行结束(CR LF)歧义。
//     CR LF 行结束序列原样保留。
//
// 仅用于 NVT 文本(command 留空的 args);SB subnegotiation 内容走 telnetEscapeBytes。
func telnetNVTData(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == scenario.TelnetIAC {
			out = append(out, scenario.TelnetIAC, scenario.TelnetIAC)
			continue
		}
		if c == '\r' {
			if i+1 < len(b) && b[i+1] == '\n' {
				// CR LF:行结束序列,原样保留,跨过 LF。
				out = append(out, '\r', '\n')
				i++
			} else {
				// 裸 CR:RFC 854 §2 归一为 CR NUL(回车不换行)。
				out = append(out, '\r', 0x00)
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// telnetEscapeBytes 仅做 IAC 转义(字面 0xFF → IAC IAC),不做 CR NUL 归一。
// 用于 SB subnegotiation 内容(option 专有二进制,如 TTYPE 终端名、NAWS),
// 这些内容不是 NVT 文本流,不套 RFC 854 的 CR 规则。
func telnetEscapeBytes(b []byte) []byte {
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
