package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// ftpConsistencyStack 是一条 FTP 控制连接的常用 stack(sport/dport=21),复用于各用例。
const ftpConsistencyStack = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.21" }
      - tcp:  { sport: 49154, dport: 21, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
`

// dataStackWith 返回一条数据连接 stack,dst IP 与 dport 由参数控制。
func dataStackWith(dstIP string, dport int) string {
	return "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv4: { src: \"10.0.0.10\", dst: \"" + dstIP + "\" }\n" +
		"      - tcp:  { sport: 49155, dport: " + itoa(dport) + ", client_isn: 700000, server_isn: 800000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// loadWarnings 走 Load + Validate + Warnings,返回告警列表(Validate 必须通过)。
func loadWarnings(t *testing.T, name, body string) []string {
	t.Helper()
	path := writeScenario(t, name, body)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load %s 失败: %v", name, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate %s 失败: %v", name, err)
	}
	return scenario.Warnings(s)
}

func containsWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestFTPConsistency_PASVMatched: 227 协商端口与 data 流 dst:dport 一致 → 无告警。
func TestFTPConsistency_PASVMatched(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,21,195,80).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "pasv_ok.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("一致场景不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_PASVPortMismatch: 227 协商 50000,data 流 dport 49999 → 端口不一致告警。
func TestFTPConsistency_PASVPortMismatch(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,21,195,80).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 49999) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "pasv_port.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "10.0.0.21:50000") {
		t.Fatalf("期望端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_PORTMismatch: PORT 协商端口与 data 流 dport 不一致 → 告警。
// 主动模式 stack 反转:数据流 src=服务器、dst=客户端,PORT 协商的是客户端 IP:port。
func TestFTPConsistency_PORTMismatch(t *testing.T) {
	control := "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv4: { src: \"10.0.0.10\", dst: \"10.0.0.21\" }\n" +
		"      - tcp:  { sport: 49156, dport: 21, client_isn: 2000, server_isn: 6000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
	// 主动模式 data 反转:src=服务器 10.0.0.21、dst=客户端 10.0.0.10;PORT 协商 10,0,0,10,192,5=49157
	data := "      - eth:  { src: \"66:77:88:99:aa:bb\", dst: \"00:11:22:33:44:55\" }\n" +
		"      - ipv4: { src: \"10.0.0.21\", dst: \"10.0.0.10\" }\n" +
		"      - tcp:  { sport: 20, dport: 49156, client_isn: 900000, server_isn: 950000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + control +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: PORT, args: \"10,0,0,10,192,5\" }\n" +
		"  - name: data\n    stack:\n" + data +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "port_mismatch.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "10.0.0.10:49157") {
		t.Fatalf("期望端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_NoDataFlow: 227 协商端口,但场景中无对应数据流 → 告警未找到数据流。
func TestFTPConsistency_NoDataFlow(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,21,195,80).\" }\n"
	warnings := loadWarnings(t, "nodata.yaml", body)
	if !containsWarning(warnings, "未找到") || !containsWarning(warnings, "10.0.0.21:50000") {
		t.Fatalf("期望未找到数据流告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_Unparseable227: 227 文本格式非标(无六元组)→ 解析失败告警。
// 畸形用例可能故意写怪格式,但用户选择"解析失败也提示",故仍产出告警。
func TestFTPConsistency_Unparseable227(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"OK\" }\n"
	warnings := loadWarnings(t, "unparseable.yaml", body)
	if !containsWarning(warnings, "未解析出") {
		t.Fatalf("期望解析失败告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_PayloadText227: 原始 payload 文本首 token "227" 也能被识别。
func TestFTPConsistency_PayloadText227(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - payload: { payload: \"227 Entering Passive Mode (10,0,0,21,195,80).\\r\\n\" }\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "payload227.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("原始 payload 227 与 data 流一致时不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_NonFTPFlowIgnored: 数据流里 payload 含 "227 ..." 字样(文件内容)
// 但该流不是控制通道候选(无 ftp_request/ftp_response 层、端口非 21),不应误告警。
func TestFTPConsistency_NonFTPFlowIgnored(t *testing.T) {
	// flow-a 非 21 端口,但其 payload 内容碰巧以 "227 ..." 开头;不应被当作 227 协商。
	nonCtrlStack := "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv4: { src: \"10.0.0.10\", dst: \"10.0.0.21\" }\n" +
		"      - tcp:  { sport: 5000, dport: 8080, client_isn: 100, server_isn: 200 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: a\n    stack:\n" + nonCtrlStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - payload: { payload: \"227 whatever (10,0,0,21,195,80)\\r\\n\" }\n"
	warnings := loadWarnings(t, "nonftp.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("非控制通道流不应被当作 227 协商扫描,实际: %v", warnings)
	}
}

// TestFTPConsistency_PASVRoleOK: 227 协商 IP=控制连接服务器侧(dst),角色一致 → 无角色告警。
func TestFTPConsistency_PASVRoleOK(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,21,195,80).\" }\n"
	warnings := loadWarnings(t, "pasv_role_ok.yaml", body)
	for _, w := range warnings {
		if strings.Contains(w, "角色") {
			t.Fatalf("227 协商 IP=服务器侧不应触发角色告警,实际: %v", warnings)
		}
	}
}

// TestFTPConsistency_PASVRoleMismatch: 227 协商 IP=客户端地址,与服务器角色不符 → 告警。
func TestFTPConsistency_PASVRoleMismatch(t *testing.T) {
	// 227 协商 10.0.0.10(控制连接客户端 src),而非服务器 dst 10.0.0.21。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,10,195,80).\" }\n"
	warnings := loadWarnings(t, "pasv_role_mismatch.yaml", body)
	if !containsWarning(warnings, "角色") || !containsWarning(warnings, "10.0.0.10") || !containsWarning(warnings, "10.0.0.21") {
		t.Fatalf("期望 227 角色不匹配告警(含 10.0.0.10 与 10.0.0.21),实际: %v", warnings)
	}
}

// TestFTPConsistency_PORTRoleMismatch: PORT 协商 IP=服务器地址,与客户端角色不符 → 告警。
func TestFTPConsistency_PORTRoleMismatch(t *testing.T) {
	// PORT 协商 10.0.0.21(控制连接服务器 dst),而非客户端 src 10.0.0.10。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: PORT, args: \"10,0,0,21,192,5\" }\n"
	warnings := loadWarnings(t, "port_role_mismatch.yaml", body)
	if !containsWarning(warnings, "角色") || !containsWarning(warnings, "10.0.0.21") || !containsWarning(warnings, "10.0.0.10") {
		t.Fatalf("期望 PORT 角色不匹配告警(含 10.0.0.21 与 10.0.0.10),实际: %v", warnings)
	}
}

// TestFTPConsistency_PORTRoleOK: PORT 协商 IP=客户端地址(src),角色一致 → 无角色告警。
func TestFTPConsistency_PORTRoleOK(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: PORT, args: \"10,0,0,10,192,5\" }\n"
	warnings := loadWarnings(t, "port_role_ok.yaml", body)
	for _, w := range warnings {
		if strings.Contains(w, "角色") {
			t.Fatalf("PORT 协商 IP=客户端侧不应触发角色告警,实际: %v", warnings)
		}
	}
}

// ---- EPSV(229)/EPRT(RFC 2428)一致性检查 ----

// ftpConsistencyStackV6 是一条 IPv6 FTP 控制连接的常用 stack(sport/dport=21)。
const ftpConsistencyStackV6 = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv6: { src: "2001:db8::10", dst: "2001:db8::21", hop_limit: 64 }
      - tcp:  { sport: 49154, dport: 21, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
`

// dataStackV6With 返回一条 IPv6 数据连接 stack,dst IPv6 与 dport 由参数控制。
func dataStackV6With(dstIP string, dport int) string {
	return "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv6: { src: \"2001:db8::10\", dst: \"" + dstIP + "\", hop_limit: 64 }\n" +
		"      - tcp:  { sport: 49155, dport: " + itoa(dport) + ", client_isn: 700000, server_isn: 800000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
}

// TestFTPConsistency_EPSVMatched: 229(EPSV)协商端口与 data 流 dport 一致;
// 地址隐式为控制连接对端(服务器 2001:db8::21)= data 流 dst → 无告警。
func TestFTPConsistency_EPSVMatched(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"Entering Extended Passive Mode (|||50000|).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "epsv_ok.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("EPSV 一致场景不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVPortMismatch: 229 协商 50000,data 流 dport 49999 → 端口不一致告警。
func TestFTPConsistency_EPSVPortMismatch(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"Entering Extended Passive Mode (|||50000|).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::21", 49999) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "epsv_port.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "2001:db8::21:50000") {
		t.Fatalf("期望 EPSV 端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVNoDataFlow: 229 协商端口,但场景中无对应数据流 → 告警未找到数据流。
func TestFTPConsistency_EPSVNoDataFlow(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"Entering Extended Passive Mode (|||50000|).\" }\n"
	warnings := loadWarnings(t, "epsv_nodata.yaml", body)
	if !containsWarning(warnings, "未找到") || !containsWarning(warnings, "2001:db8::21:50000") {
		t.Fatalf("期望 EPSV 未找到数据流告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVUnparseable: 229 文本非标(无 (|||port|))→ 解析失败告警。
func TestFTPConsistency_EPSVUnparseable(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"OK\" }\n"
	warnings := loadWarnings(t, "epsv_unparseable.yaml", body)
	if !containsWarning(warnings, "未解析出") {
		t.Fatalf("期望 EPSV 解析失败告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVRoleNoWarn: 229 不含地址,无角色可比对 → 不产出角色告警。
func TestFTPConsistency_EPSVRoleNoWarn(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"Entering Extended Passive Mode (|||50000|).\" }\n"
	warnings := loadWarnings(t, "epsv_role.yaml", body)
	for _, w := range warnings {
		if strings.Contains(w, "角色") {
			t.Fatalf("EPSV(229)不含地址,不应触发角色告警,实际: %v", warnings)
		}
	}
}

// TestFTPConsistency_EPRTMatched: EPRT 协商(IPv6 地址:端口)与 data 流 dst 一致 → 无告警。
func TestFTPConsistency_EPRTMatched(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8::10|49157|\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::10", 49157) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "eprt_ok.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("EPRT 一致场景不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTPortMismatch: EPRT 协商 49157,data 流 dport 49999 → 端口不一致告警。
func TestFTPConsistency_EPRTPortMismatch(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8::10|49157|\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::10", 49999) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "eprt_port.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "2001:db8::10:49157") {
		t.Fatalf("期望 EPRT 端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTRoleMismatch: EPRT 协商 IP=服务器地址,与客户端角色不符 → 角色告警。
func TestFTPConsistency_EPRTRoleMismatch(t *testing.T) {
	// EPRT 协商 2001:db8::21(控制连接服务器 dst),而非客户端 src 2001:db8::10。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8::21|49157|\" }\n"
	warnings := loadWarnings(t, "eprt_role_mismatch.yaml", body)
	if !containsWarning(warnings, "角色") || !containsWarning(warnings, "2001:db8::21") || !containsWarning(warnings, "2001:db8::10") {
		t.Fatalf("期望 EPRT 角色不匹配告警(含 2001:db8::21 与 2001:db8::10),实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTRoleOK: EPRT 协商 IP=客户端地址(src),角色一致 → 无角色告警。
func TestFTPConsistency_EPRTRoleOK(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8::10|49157|\" }\n"
	warnings := loadWarnings(t, "eprt_role_ok.yaml", body)
	for _, w := range warnings {
		if strings.Contains(w, "角色") {
			t.Fatalf("EPRT 协商 IP=客户端侧不应触发角色告警,实际: %v", warnings)
		}
	}
}

// TestFTPConsistency_EPRTRoleMismatchIPv4: EPRT netproto=1(IPv4)也能正确解析与角色校验。
func TestFTPConsistency_EPRTRoleMismatchIPv4(t *testing.T) {
	// IPv4 控制连接 + EPRT netproto=1,协商服务器地址 → 角色告警。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|1|10.0.0.21|49157|\" }\n"
	warnings := loadWarnings(t, "eprt_v4_role_mismatch.yaml", body)
	if !containsWarning(warnings, "角色") || !containsWarning(warnings, "10.0.0.21") || !containsWarning(warnings, "10.0.0.10") {
		t.Fatalf("期望 EPRT(IPv4)角色不匹配告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTBadNetproto: EPRT netproto 非 1/2 → 解析失败告警。
func TestFTPConsistency_EPRTBadNetproto(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|3|2001:db8::10|49157|\" }\n"
	warnings := loadWarnings(t, "eprt_bad_proto.yaml", body)
	if !containsWarning(warnings, "未解析出") {
		t.Fatalf("期望 EPRT 非法 netproto 解析失败告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVPayloadText: 原始 payload 文本首 token "229" 也能被识别。
func TestFTPConsistency_EPSVPayloadText(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - payload: { payload: \"229 Entering Extended Passive Mode (|||50000|).\\r\\n\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "payload229.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("原始 payload 229 与 data 流一致时不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTPayloadText: 原始 payload 文本首 token "EPRT" 也能被识别。
// 原始文本含 CRLF 行尾,parseEPRTArgs 须先剥行尾与 "EPRT " 命令前缀再匹配。
func TestFTPConsistency_EPRTPayloadText(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - payload: { payload: \"EPRT |2|2001:db8::10|49157|\\r\\n\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::10", 49157) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "payloadeprt.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("原始 payload EPRT 与 data 流一致时不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTAddrNormalization: EPRT 用非规范 IPv6 文本(完整展开形式)
// 与 data 流 dst 简写比对时,归一化后一致 → 无告警。验证协商侧地址规范化逻辑。
func TestFTPConsistency_EPRTAddrNormalization(t *testing.T) {
	// EPRT 协商 |2|2001:db8:0:0:0:0:0:10|49157|(完整展开),data 流 dst 用简写 2001:db8::10。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8:0:0:0:0:0:10|49157|\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::10", 49157) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "eprt_norm.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("EPRT 地址归一化后一致不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPRTAddrNormalizationFlowSide: 控制流 src 用完整展开形式、
// EPRT 协商用简写时,角色校验(协商 IP vs 控制流 src IP)归一化后一致 → 无角色告警。
// 验证 flow 端点地址也走了规范化(不仅协商侧归一化)。
func TestFTPConsistency_EPRTAddrNormalizationFlowSide(t *testing.T) {
	// 控制流 src=2001:db8:0:0:0:0:0:10(完整展开),EPRT 协商 2001:db8::10(简写)→ 同一地址。
	stack := "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv6: { src: \"2001:db8:0:0:0:0:0:10\", dst: \"2001:db8::21\", hop_limit: 64 }\n" +
		"      - tcp:  { sport: 49154, dport: 21, client_isn: 1000, server_isn: 5000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + stack +
		"    messages:\n      - from: src\n        stack:\n" +
		"          - ftp_request: { command: EPRT, args: \"|2|2001:db8::10|49157|\" }\n"
	warnings := loadWarnings(t, "eprt_norm_flow.yaml", body)
	for _, w := range warnings {
		if strings.Contains(w, "角色") {
			t.Fatalf("协商地址与控制流 src 是同一 IPv6(不同文本形式),不应触发角色告警,实际: %v", warnings)
		}
	}
}

// TestFTPConsistency_NonFirstLayer: 227 协商层放在 message.stack 的非首层(stack[1],
// 前面垫一个 payload 层)。多 payload 生产层放开后,协商端点仍须被提取并参与一致性校验,
// 否则假阴性。验证非首层的 227 与 data 流端口不一致仍告警。
func TestFTPConsistency_NonFirstLayer(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - payload: { payload: \"multiline preamble\\r\\n\" }\n" +
		"          - ftp_response: { code: 227, message: \"Entering Passive Mode (10,0,0,21,195,80).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 49999) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "nonfirst.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "10.0.0.21:50000") {
		t.Fatalf("期望非首层 227 端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_227LinesMultiline: 227 的六元组在多行续行 lines 里(message 为空、
// lines 承载正文)。extractFTPNegotiations 合并 message+lines 后再解析,覆盖 lines 遍历分支。
func TestFTPConsistency_227LinesMultiline(t *testing.T) {
	// 227 续行:首行 code-text,末行含六元组(RFC 959 续行格式)。
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 227, lines: [\"Entering Passive Mode\", \"(10,0,0,21,195,80).\"] }\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "227lines.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("227 六元组在 lines 里与 data 流一致时不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_229LinesMultiline: 229(EPSV)的 (|||port|) 在多行续行 lines 里,
// 覆盖 229 的 lines 遍历分支。地址隐式为控制连接对端,data 流 dst 一致 → 无告警。
func TestFTPConsistency_229LinesMultiline(t *testing.T) {
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStackV6 +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, lines: [\"Entering Extended Passive Mode\", \"(|||50000|).\"] }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "229lines.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("229 (|||port|) 在 lines 里与 data 流一致时不应告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_NonFirstLayerPayloadHex: 227 协商用 payload_hex 放在非首层(stack[1]),
// 前面垫一个 payload 层。验证 payload_hex 非首层仍被解码提取并参与校验(覆盖非首层
// payload_hex 解码 + ftpNegotiationKind 识别分支),端口不一致仍告警。
func TestFTPConsistency_NonFirstLayerPayloadHex(t *testing.T) {
	// "227 Entering Passive Mode (10,0,0,21,195,80).\r\n" 的 hex。
	const hex227 = "0x32323720456e746572696e672050617373697665204d6f6465202831302c302c302c32312c3139352c3830292e0d0a"
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ftpConsistencyStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - payload: { payload: \"preamble\\r\\n\" }\n" +
		"          - payload_hex: " + hex227 + "\n" +
		"  - name: data\n    stack:\n" + dataStackWith("10.0.0.21", 49999) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "nonfirst_phex.yaml", body)
	if !containsWarning(warnings, "端口不一致") || !containsWarning(warnings, "10.0.0.21:50000") {
		t.Fatalf("期望非首层 payload_hex 227 端口不一致告警,实际: %v", warnings)
	}
}

// TestFTPConsistency_EPSVAddrNormalizationFlowSide: EPSV(229)不含地址,隐式取控制流
// dst IP;控制流 dst 用完整展开、data 流 dst 用简写时,归一化后一致 → 无告警。
// 验证 229 隐式地址比对时两侧都走了规范化。
func TestFTPConsistency_EPSVAddrNormalizationFlowSide(t *testing.T) {
	ctrlStack := "      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
		"      - ipv6: { src: \"2001:db8::10\", dst: \"2001:db8:0:0:0:0:0:21\", hop_limit: 64 }\n" +
		"      - tcp:  { sport: 49154, dport: 21, client_isn: 1000, server_isn: 5000 }\n" +
		"      - tcp_session: { open: handshake, close: fin }\n"
	body := "link_type: ethernet\nseed: 42\nflows:\n" +
		"  - name: control\n    stack:\n" + ctrlStack +
		"    messages:\n      - from: dst\n        stack:\n" +
		"          - ftp_response: { code: 229, message: \"Entering Extended Passive Mode (|||50000|).\" }\n" +
		"  - name: data\n    stack:\n" + dataStackV6With("2001:db8::21", 50000) +
		"    messages:\n      - from: dst\n        stack:\n          - payload: { payload: \"x\" }\n"
	warnings := loadWarnings(t, "epsv_norm_flow.yaml", body)
	if len(warnings) != 0 {
		t.Fatalf("EPSV 隐式地址与 data 流 dst 是同一 IPv6(不同文本形式),不应告警,实际: %v", warnings)
	}
}
