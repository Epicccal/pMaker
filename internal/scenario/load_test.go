package scenario_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// writeScenario 把 yaml 写进临时文件并返回路径,供 scenario.Load 走完整解析路径。
func writeScenario(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestLoadRejectsUnknownSegmentFields 验证 segment 的未实现字段(order/overlap/retransmit)
// 在解析层被拒,并带字段名。
func TestLoadRejectsUnknownSegmentFields(t *testing.T) {
	path := writeScenario(t, "seg.yaml", `link_type: ethernet
seed: 42
flows:
  - name: f
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        segment: { mss: 8, order: shuffled, overlap: 4, retransmit: [1] }
        stack:
          - payload_hex: "0xdeadbeef"
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatal("期望 Load 拒绝未实现的 segment 字段(order/overlap/retransmit),实际通过")
	}
	// 报错应点名至少一个未实现字段,且带文件路径包装。
	for _, want := range []string{"order", "overlap", "retransmit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应包含字段 %q,得到: %v", want, err)
		}
	}
}

// TestLoadRejectsTypoLayerField 验证 layer 内子字段(如 eth.scr 拼写错误)也被解析层拒绝,
// 并带字段名。覆盖 decodeKnownFields 对 layer 子树的校验。
func TestLoadRejectsTypoLayerField(t *testing.T) {
	path := writeScenario(t, "typo.yaml", `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { scr: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatal("期望 Load 拒绝拼错字段 eth.scr,实际通过")
	}
	if !strings.Contains(err.Error(), "scr") {
		t.Errorf("错误信息应点名拼错字段 scr,得到: %v", err)
	}
}

// TestLoadRejectsUnknownGREField 验证无字段层(GREFields)拒绝任意子字段
// (如 gre: { foo: 1 })。
func TestLoadRejectsUnknownGREField(t *testing.T) {
	path := writeScenario(t, "gre.yaml", `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - gre:  { foo: 1 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	_, err := scenario.Load(path)
	if err == nil {
		t.Fatal("期望 Load 拒绝 gre 层未知字段 foo,实际通过")
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("错误信息应点名未知字段 foo,得到: %v", err)
	}
}

// TestLoadAcceptsValidScenario 回归保护:合法场景不被未知字段校验误伤。
func TestLoadAcceptsValidScenario(t *testing.T) {
	path := writeScenario(t, "ok.yaml", `link_type: ethernet
seed: 42
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 1234, dport: 80, flags: [SYN] }
`)
	if _, err := scenario.Load(path); err != nil {
		t.Fatalf("合法场景应通过 KnownFields 校验,实际失败: %v", err)
	}
}
