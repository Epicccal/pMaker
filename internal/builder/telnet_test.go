package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 TELNET 应用层序列化(builder/telnet.go):
// 各 command 字节输出(协商三字节、控制二字节、SB IS/SEND、NAWS 大端、text 转义、多层拼接)。
// 与 ftp_test.go 同构:回读 examples/telnet/*.yaml 断言 TCP payload 字节。

// IAC 与 TELNET 字节常量(RFC 854),与 scenario 包导出值一致,用于断言。
const (
	iac  = 0xFF
	sb   = 0xFA
	se   = 0xF0
	will = 0xFB
	wont = 0xFC
	doC  = 0xFD
	dont = 0xFE
)

// TestTelnetNVTText 回读 nvt_text.yaml,断言纯 NVT 文本 args 原样输出。
func TestTelnetNVTText(t *testing.T) {
	data, _ := genPcap(t, "../../examples/telnet/nvt_text.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	app := pkts[0].ApplicationLayer()
	if app == nil || string(app.Payload()) != "login: " {
		t.Errorf("NVT 文本=%q,期望 \"login: \"", app)
	}
}

// TestTelnetNegotiation 回读 negotiation.yaml,断言四个 IAC 协商命令三字节编码并顺序拼接。
func TestTelnetNegotiation(t *testing.T) {
	data, _ := genPcap(t, "../../examples/telnet/negotiation.yaml")
	pkts := readPackets(t, data)
	app := pkts[0].ApplicationLayer()
	want := []byte{iac, will, 1, iac, will, 3, iac, doC, 3, iac, dont, 1}
	if app == nil || !bytes.Equal(app.Payload(), want) {
		t.Errorf("协商流=%v,期望 %v", app, want)
	}
}

// TestTelnetControlSignals 回读 control_signals.yaml,断言十个二字节控制命令拼接。
func TestTelnetControlSignals(t *testing.T) {
	data, _ := genPcap(t, "../../examples/telnet/control_signals.yaml")
	pkts := readPackets(t, data)
	app := pkts[0].ApplicationLayer()
	// GA=0xF9 BRK=0xF3 IP=0xF4 AO=0xF5 AYT=0xF6 EC=0xF7 EL=0xF8 NOP=0xF1 DM=0xF2 EOR=0xEF
	want := []byte{
		iac, 0xF9, iac, 0xF3, iac, 0xF4, iac, 0xF5, iac, 0xF6,
		iac, 0xF7, iac, 0xF8, iac, 0xF1, iac, 0xF2, iac, 0xEF,
	}
	if app == nil || !bytes.Equal(app.Payload(), want) {
		t.Errorf("控制命令流=%v,期望 %v", app, want)
	}
}

// TestTelnetTTypeNAWS 回读 ttype_naws.yaml,断言 SB TTYPE IS(自动前缀 IS)与 SB NAWS 大端字节。
func TestTelnetTTypeNAWS(t *testing.T) {
	data, _ := genPcap(t, "../../examples/telnet/ttype_naws.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}
	// ① TTYPE IS: IAC SB 24 00 "xterm-256color" IAC SE
	app0 := pkts[0].ApplicationLayer()
	want0 := append([]byte{iac, sb, 24, 0x00}, []byte("xterm-256color")...)
	want0 = append(want0, iac, se)
	if app0 == nil || !bytes.Equal(app0.Payload(), want0) {
		t.Errorf("TTYPE IS=%v,期望 %v", app0, want0)
	}
	// ② NAWS 80x24: IAC SB 31 00 50 00 18 IAC SE
	app1 := pkts[1].ApplicationLayer()
	want1 := []byte{iac, sb, 31, 0x00, 0x50, 0x00, 0x18, iac, se}
	if app1 == nil || !bytes.Equal(app1.Payload(), want1) {
		t.Errorf("NAWS=%v,期望 %v", app1, want1)
	}
}

// TestTelnetTextEscape 验证 IAC 转义:args 含字面 0xFF 时输出 IAC IAC(0xFF 0xFF)。
// 用 nvt_text 的 standalone 风格构造一个含 0xFF 的 telnet 层(走完整链路)。
func TestTelnetTextEscape(t *testing.T) {
	// 直接用 scenario -> builder 链路:构造含 0xFF 的 NVT 文本。
	// 0xFF 在 UTF-8 下是非法字节,这里用 \xff 通过 payload 文本字段注入。
	s := mustBuildPcapWithTelnetText(t, "\xff\xffhello")
	pkts := readPackets(t, s)
	app := pkts[0].ApplicationLayer()
	// 两个 0xFF 各转义为 IAC IAC,故:ff ff ff ff h e l l o
	want := []byte{iac, iac, iac, iac, 'h', 'e', 'l', 'l', 'o'}
	if app == nil || !bytes.Equal(app.Payload(), want) {
		t.Errorf("转义输出=%v,期望 %v", app, want)
	}
}

// TestTelnetTextArgsHex 验证纯 NVT 文本(command 空)走 args_hex 时,原始字节原样落盘、不转义。
// 回归用例:此前 serializeTelnet 的纯文本分支只读 args、静默丢弃 args_hex(校验却放行),
// 导致 payload 为空。修复后 args_hex 内容应完整出现(含字面 0xFF,刻意不转义以构造畸形流量)。
func TestTelnetTextArgsHex(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
				// 0x414243 = "ABC";0xff 字面字节不转义(畸形/非转义 NVT 文本)。
				{Type: "telnet", Fields: &scenario.TelnetFields{ArgsHex: "0x414243ff"}},
			},
		}},
	}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	app := pkts[0].ApplicationLayer()
	want := []byte{0x41, 0x42, 0x43, 0xff}
	if app == nil || !bytes.Equal(app.Payload(), want) {
		t.Errorf("args_hex 纯文本输出=%v,期望 %v", app, want)
	}
}

// TestTelnetTextCRNormalization 验证 RFC 854 §2 的 CR 归一:
//   - 裸 CR(后非 LF)→ CR NUL(0x0d 0x00),表示"回车不换行",避免与行结束歧义;
//   - CR LF 行结束序列原样保留;
//   - 末尾裸 CR 也归一为 CR NUL。
//
// 仅作用于 NVT 文本(command 留空的 args);SB 内容不套此规则。
func TestTelnetTextCRNormalization(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		want []byte
	}{
		{"行结束保留", "abc\r\n", []byte("abc\r\n")},
		{"裸 CR 归一 CR NUL", "ab\rcd", []byte("ab\r\x00cd")},
		{"末尾裸 CR 归一 CR NUL", "abc\r", []byte("abc\r\x00")},
		{"多个行结束", "a\r\nb\r\n", []byte("a\r\nb\r\n")},
		{"CR+IAC 混合", "\r\xff", []byte("\r\x00\xff\xff")},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkts := readPackets(t, mustBuildPcapWithTelnetText(t, c.text))
			app := pkts[0].ApplicationLayer()
			if app == nil || !bytes.Equal(app.Payload(), c.want) {
				t.Errorf("输出=%v,期望 %v", app, c.want)
			}
		})
	}
}

// TestTelnetSBContentNoCRNormalization 验证 SB subnegotiation 内容只做 IAC 转义,
// 不套 NVT 的 CR NUL 归一(SB 内容是 option 专有二进制,非 NVT 文本流)。
// 用非 TTYPE option + args 含裸 CR,断言 CR 原样保留(不补 NUL)。
func TestTelnetSBContentNoCRNormalization(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
				// NEW_ENVIRON(option 39)SB,内容含裸 CR:应原样保留(不归一为 CR NUL)。
				{Type: "telnet", Fields: &scenario.TelnetFields{Command: "SB", Option: "NEW_ENVIRON", Args: "a\rb"}},
			},
		}},
	}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	app := pkts[0].ApplicationLayer()
	// IAC SB 39 'a' CR 'b' IAC SE —— CR 不补 NUL。
	want := []byte{iac, sb, 39, 'a', '\r', 'b', iac, se}
	if app == nil || !bytes.Equal(app.Payload(), want) {
		t.Errorf("SB 内容输出=%v,期望 %v(裸 CR 不归一)", app, want)
	}
}

// mustBuildPcapWithTelnetText 构造一个 standalone packet(eth/ipv4/tcp/telnet),
// telnet 层为纯 NVT 文本(args=text),跑完整链路返回 pcap 字节。用于测试 IAC 转义。
func mustBuildPcapWithTelnetText(t *testing.T, text string) []byte {
	t.Helper()
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
				{Type: "telnet", Fields: &scenario.TelnetFields{Args: text}},
			},
		}},
	}
	return buildScenarioPcap(t, s)
}

// TestTelnetMalformed 回读 malformed.yaml,断言 payload_hex 原始字节原样落盘(不转义/不修正)。
func TestTelnetMalformed(t *testing.T) {
	data, _ := genPcap(t, "../../examples/telnet/malformed.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(pkts))
	}
	// ① IAC + 未知码 0xAA
	if app := pkts[0].ApplicationLayer(); app == nil || !bytes.Equal(app.Payload(), []byte{0xff, 0xaa}) {
		t.Errorf("非法 IAC 序列=%v", app)
	}
	// ② SB 内容含未转义 0xFF
	if app := pkts[1].ApplicationLayer(); app == nil || !bytes.Equal(app.Payload(), []byte{0xff, 0xfa, 0x18, 0xff, 0x78, 0xff, 0xf0}) {
		t.Errorf("未转义 FF=%v", app)
	}
	// ③ 非标 option 200: IAC WILL 200
	if app := pkts[2].ApplicationLayer(); app == nil || !bytes.Equal(app.Payload(), []byte{iac, will, 200}) {
		t.Errorf("私有 option=%v", app)
	}
}
