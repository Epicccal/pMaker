package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// tftp_consistency_test.go 覆盖 tftp 层的五条一致性软告警:
// RQ 端口 / mode 废弃与未知 / DATA 超长 / 无关字段。

// tftpWarn 用例走 Load + Validate + Warnings,断言告警文案含 want。
func tftpWarn(t *testing.T, body, wantSubstr string) []scenario.Diagnostic {
	t.Helper()
	s, err := scenario.Load(writeScenario(t, "tftp-warn.yaml", body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ws := scenario.Warnings(s)
	if wantSubstr == "" {
		return ws
	}
	found := false
	for _, w := range ws {
		if strings.Contains(w.Message, wantSubstr) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("期望告警含 %q,得到: %v", wantSubstr, ws)
	}
	return ws
}

// TestTFTPWarnings_RQPort:RRQ dport 69 无告警;非 69 告警 tftp.rq-port。
func TestTFTPWarnings_RQPort(t *testing.T) {
	ok := tftpWarn(t, "link_type: ethernet\npackets:\n  - stack:\n"+
		"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n"+
		"      - ipv4: { src: \"10.0.0.1\", dst: \"10.0.0.2\", ttl: 64 }\n"+
		"      - udp:  { sport: 40000, dport: 69 }\n"+
		"      - tftp: { opcode: rrq, filename: \"a.txt\" }\n", "")
	if len(ok) != 0 {
		t.Fatalf("dport 69 不应告警,得到: %v", ok)
	}
	tftpWarn(t, "link_type: ethernet\npackets:\n  - stack:\n"+
		"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n"+
		"      - ipv4: { src: \"10.0.0.1\", dst: \"10.0.0.2\", ttl: 64 }\n"+
		"      - udp:  { sport: 40000, dport: 80 }\n"+
		"      - tftp: { opcode: rrq, filename: \"a.txt\" }\n",
		"RFC 1350 规定 RRQ/WRQ 发往服务器 69 端口")
}

// TestTFTPWarnings_Mode:octet/OCTET 无告警;mail/MAIL 产 obsolete;binary 产 unknown。
func TestTFTPWarnings_Mode(t *testing.T) {
	base := func(mode string) string {
		return "link_type: ethernet\npackets:\n  - stack:\n" +
			"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n" +
			"      - ipv4: { src: \"10.0.0.1\", dst: \"10.0.0.2\", ttl: 64 }\n" +
			"      - udp:  { sport: 40000, dport: 69 }\n" +
			"      - tftp: { opcode: rrq, filename: \"a.txt\", mode: " + mode + " }\n"
	}
	// octet 与 OCTET:大小写折叠后命中,均无告警(决策 B)。
	for _, mode := range []string{"octet", "OCTET"} {
		ws := tftpWarn(t, base(mode), "")
		if len(ws) != 0 {
			t.Fatalf("mode %s 不应告警,得到: %v", mode, ws)
		}
	}
	// mail 与 MAIL:折叠命中,产 tftp.mode-obsolete(而非 unknown)。
	for _, mode := range []string{"mail", "MAIL"} {
		ws := tftpWarn(t, base("\""+mode+"\""), "已废弃的 mail 模式")
		for _, w := range ws {
			if w.Code != "tftp.mode-obsolete" {
				t.Fatalf("mode %s 应产 tftp.mode-obsolete,得到 %s: %s", mode, w.Code, w.Message)
			}
		}
	}
	// binary:折叠后不在已知集合,产 tftp.mode-unknown。
	ws := tftpWarn(t, base("binary"), "不在已知集合")
	for _, w := range ws {
		if w.Code != "tftp.mode-unknown" {
			t.Fatalf("binary 应产 tftp.mode-unknown,得到 %s: %s", w.Code, w.Message)
		}
	}
}

// TestTFTPWarnings_DataOversize:DATA > 512 字节产 tftp.data-oversize。
func TestTFTPWarnings_DataOversize(t *testing.T) {
	ws := tftpWarn(t, "link_type: ethernet\npackets:\n  - stack:\n"+
		"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n"+
		"      - ipv4: { src: \"10.0.0.1\", dst: \"10.0.0.2\", ttl: 64 }\n"+
		"      - udp:  { sport: 54321, dport: 50000 }\n"+
		"      - tftp: { opcode: data, block: 1, data: \""+strings.Repeat("x", 513)+"\" }\n",
		"超过 RFC 1350 默认 block_size 512")
	for _, w := range ws {
		if w.Code != "tftp.data-oversize" {
			t.Fatalf("应产 tftp.data-oversize,得到 %s: %s", w.Code, w.Message)
		}
	}
}

// TestTFTPWarnings_FieldIgnored:ack 写 data 产 tftp.field-ignored;字段集外无告警。
func TestTFTPWarnings_FieldIgnored(t *testing.T) {
	ws := tftpWarn(t, "link_type: ethernet\npackets:\n  - stack:\n"+
		"      - eth:  { src: \"00:11:22:33:44:55\", dst: \"66:77:88:99:aa:bb\" }\n"+
		"      - ipv4: { src: \"10.0.0.1\", dst: \"10.0.0.2\", ttl: 64 }\n"+
		"      - udp:  { sport: 54321, dport: 50000 }\n"+
		"      - tftp: { opcode: ack, block: 1, data: \"ignored\" }\n",
		"与 opcode=ack 无关")
	for _, w := range ws {
		if w.Code != "tftp.field-ignored" {
			t.Fatalf("应产 tftp.field-ignored,得到 %s: %s", w.Code, w.Message)
		}
	}
}

// TestTFTPWarnings_RQPortSkipsDstFlow:flow 中 from: dst 的请求消息端点已交换,
// 不参与 RQ 端口检查。
func TestTFTPWarnings_RQPortSkipsDstFlow(t *testing.T) {
	// dport 50000(客户端 TID)在 from: dst 下不告警;若误判会产 rq-port。
	ws := tftpWarn(t, "link_type: ethernet\nflows:\n  - name: f\n    stack:\n"+tftpUDPStack+
		"    messages:\n      - from: dst\n        stack:\n"+
		"          - tftp: { opcode: ack, block: 1 }\n", "")
	if len(ws) != 0 {
		t.Fatalf("from: dst 的消息不应触发 RQ 端口检查,得到: %v", ws)
	}
}
