package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 telnet_command.go 的 TELNET 命令 / option 合法基线校验:
// 已知命令(大小写不敏感)、数字回退、未知报错并引导 payload / payload_hex;
// 协商必带 option、控制命令禁带 option/args、args/args_hex 互斥等结构约束。
// 与 ftp_command_test.go 同构。

// telnetLayer 包装一条 telnet 层,便于表驱动构造。
func telnetLayer(cmd, opt, args, argsHex string) scenario.Layer {
	return scenario.Layer{Type: "telnet", Fields: &scenario.TelnetFields{
		Command: cmd, Option: opt, Args: args, ArgsHex: argsHex,
	}}
}

// telnetBaseStack 是承载 TELNET 校验的最小合法 stack(eth/ipv4/tcp)。
func telnetBaseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
		layer,
	}
}

func telnetValidate(t *testing.T, layer scenario.Layer) error {
	t.Helper()
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: telnetBaseStack(layer)}}}
	return scenario.Validate(s)
}

// TestValidateTelnet_KnownAccepts: 已知命令 + option 组合均通过(大小写不敏感)。
func TestValidateTelnet_KnownAccepts(t *testing.T) {
	for _, c := range []struct{ cmd, opt, args string }{
		{"WILL", "ECHO", ""},
		{"will", "echo", ""},
		{"DO", "SGA", ""},
		{"DONT", "TTYPE", ""},
		{"SB", "TTYPE", "xterm"},
		{"SB", "NAWS", ""},
		{"GA", "", ""},
		{"BRK", "", ""},
		{"NOP", "", ""},
	} {
		layer := telnetLayer(c.cmd, c.opt, c.args, "")
		if c.cmd == "SB" && c.opt == "NAWS" {
			// NAWS 需 args_hex(二进制大端)。
			layer = telnetLayer("SB", "NAWS", "", "0x00500018")
		}
		if err := telnetValidate(t, layer); err != nil {
			t.Errorf("已知组合 cmd=%q opt=%q 应通过,得到: %v", c.cmd, c.opt, err)
		}
	}
}

// TestValidateTelnet_UnknownCommandRejects: 未知命令报错并引导 payload/payload_hex。
func TestValidateTelnet_UnknownCommandRejects(t *testing.T) {
	for _, cmd := range []string{"XYZ", "FOO"} {
		err := telnetValidate(t, telnetLayer(cmd, "ECHO", "", ""))
		if err == nil {
			t.Fatalf("未知命令 %q 应被拒,实际通过", cmd)
		}
		if !strings.Contains(err.Error(), cmd) {
			t.Errorf("错误应点名命令 %q,得到: %v", cmd, err)
		}
		if !strings.Contains(err.Error(), "payload") || !strings.Contains(err.Error(), "payload_hex") {
			t.Errorf("错误应引导 payload / payload_hex,得到: %v", err)
		}
	}
}

// TestValidateTelnet_NumberFallback: option 数字回退(私有码 200)通过。
func TestValidateTelnet_NumberFallback(t *testing.T) {
	for _, opt := range []string{"200", "0xc8", "0xff"} {
		// 0xc8=200、0xff=255 均在单字节范围内,合法。
		if err := telnetValidate(t, telnetLayer("WILL", opt, "", "")); err != nil {
			t.Errorf("数字 option %q 应通过,得到: %v", opt, err)
		}
	}
	// 越界数字应报错。
	if err := telnetValidate(t, telnetLayer("WILL", "256", "", "")); err == nil {
		t.Errorf("option 256 越界应报错")
	}
}

// TestValidateTelnet_NegotiationRequiresOption: WILL/WONT/DO/DONT/SB 缺 option 报错。
func TestValidateTelnet_NegotiationRequiresOption(t *testing.T) {
	for _, cmd := range []string{"WILL", "WONT", "DO", "DONT", "SB"} {
		err := telnetValidate(t, telnetLayer(cmd, "", "x", ""))
		if err == nil || !strings.Contains(err.Error(), "option") {
			t.Errorf("%s 缺 option 应报错,得到: %v", cmd, err)
		}
	}
}

// TestValidateTelnet_ControlForbidsOptionArgs: 二字节控制命令禁带 option/args。
func TestValidateTelnet_ControlForbidsOptionArgs(t *testing.T) {
	for _, cmd := range []string{"GA", "BRK", "IP", "AO", "AYT", "EC", "EL", "NOP", "DM", "EOR"} {
		if err := telnetValidate(t, telnetLayer(cmd, "ECHO", "", "")); err == nil {
			t.Errorf("控制命令 %s 不应带 option", cmd)
		}
		if err := telnetValidate(t, telnetLayer(cmd, "", "data", "")); err == nil {
			t.Errorf("控制命令 %s 不应带 args", cmd)
		}
		// 纯控制命令(无 option/args)应通过。
		if err := telnetValidate(t, telnetLayer(cmd, "", "", "")); err != nil {
			t.Errorf("控制命令 %s 纯净应通过,得到: %v", cmd, err)
		}
	}
}

// TestValidateTelnet_ArgsMutex: args 与 args_hex 互斥。
func TestValidateTelnet_ArgsMutex(t *testing.T) {
	err := telnetValidate(t, telnetLayer("SB", "TTYPE", "xterm", "0x00"))
	if err == nil || !strings.Contains(err.Error(), "只能配置一个") {
		t.Errorf("args 与 args_hex 互斥应报错,得到: %v", err)
	}
}

// TestValidateTelnet_TextRequiresArgs: 纯文本(command 空)须有 args。
func TestValidateTelnet_TextRequiresArgs(t *testing.T) {
	err := telnetValidate(t, telnetLayer("", "", "", ""))
	if err == nil {
		t.Errorf("纯文本缺 args 应报错")
	}
	// 纯文本带 option 应报错。
	if err := telnetValidate(t, telnetLayer("", "ECHO", "x", "")); err == nil {
		t.Errorf("纯文本带 option 应报错")
	}
}

// TestValidateTelnet_SBRequiresContent: SB 须有 args 或 args_hex。
func TestValidateTelnet_SBRequiresContent(t *testing.T) {
	err := telnetValidate(t, telnetLayer("SB", "TTYPE", "", ""))
	if err == nil || !strings.Contains(err.Error(), "subneg") {
		t.Errorf("SB 缺内容应报错,得到: %v", err)
	}
}

// TestValidateTelnet_NegotiationForbidsArgs: 协商(WILL 等)不带 args。
func TestValidateTelnet_NegotiationForbidsArgs(t *testing.T) {
	if err := telnetValidate(t, telnetLayer("WILL", "ECHO", "data", "")); err == nil {
		t.Errorf("WILL 协商不应带 args")
	}
}

// TestValidateTelnet_ArgsHexParse: args_hex 非法格式报错。
func TestValidateTelnet_ArgsHexParse(t *testing.T) {
	if err := telnetValidate(t, telnetLayer("SB", "NAWS", "", "0xZZ")); err == nil {
		t.Errorf("非法 args_hex 应报错")
	}
}
