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
