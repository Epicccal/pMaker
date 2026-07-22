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

// loadValid 走 Load + Validate 全路径(语义校验在 Validate,不在 Load/KnownFields)。
func loadValid(t *testing.T, name, body string) *scenario.Scenario {
	t.Helper()
	path := writeScenario(t, name, body)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load %s 失败: %v", name, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate %s 失败: %v", name, err)
	}
	return s
}

const flowStackYAML = `      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
`

// TestValidateRejectsDuplicateMessageID 验证同一 flow 内 message_id 重复被 Validate 拒,
// 并带字段名 + id 值。
func TestValidateRejectsDuplicateMessageID(t *testing.T) {
	path := writeScenario(t, "dupmsgid.yaml", "link_type: ethernet\nseed: 42\nflows:\n  - name: f\n    stack:\n"+flowStackYAML+`    messages:
      - from: src
        message_id: dup
        stack:
          - payload: { payload: "aaaa" }
      - from: dst
        message_id: dup
        stack:
          - payload: { payload: "bbbb" }
`)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	err = scenario.Validate(s)
	if err == nil {
		t.Fatal("期望 Validate 拒绝同一 flow 内重复 message_id,实际通过")
	}
	for _, want := range []string{"message_id", "dup", "重复"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应包含 %q,得到: %v", want, err)
		}
	}
}

// TestValidateAcceptsMessageID 验证 message_id 可选、不设与唯一设置都通过 Validate。
func TestValidateAcceptsMessageID(t *testing.T) {
	loadValid(t, "okmsgid.yaml", "link_type: ethernet\nseed: 42\nflows:\n  - name: f\n    stack:\n"+flowStackYAML+`    messages:
      - from: src
        message_id: first
        stack:
          - payload: { payload: "aaaa" }
      - from: dst
        message_id: second
        stack:
          - payload: { payload: "bbbb" }
      - from: src
        stack:
          - payload: { payload: "cccc" }
`)
}

// startAfterScenario 用模板 + 给定的两条 flow YAML 段拼一个场景,供 start_after 校验测试。
func startAfterScenario(flowsYAML string) string {
	return "link_type: ethernet\nseed: 42\nflows:\n" + flowsYAML
}

// twoFlowYAML 生成两条 flow:第一条(name=control)的 dst 消息带 message_id: pasv;
// 第二条(name=data)的 start_after 由参数给出。用于各种 start_after 引用校验。
func twoFlowYAML(startAfter string) string {
	return "  - name: control\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "PASV" }
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "227" }
  - name: data
    start_after: "` + startAfter + `"
    stack:
` + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "data" }
`
}

// loadValidateErr 走 Load + Validate,返回 error(nil 表示通过)。
func loadValidateErr(t *testing.T, name, body string) error {
	t.Helper()
	path := writeScenario(t, name, body)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load %s 失败(应可解析): %v", name, err)
	}
	return scenario.Validate(s)
}

func TestStartAfterAcceptsValid(t *testing.T) {
	if err := loadValidateErr(t, "ok.yaml", startAfterScenario(twoFlowYAML("control.pasv"))); err != nil {
		t.Fatalf("合法 start_after 应通过 Validate: %v", err)
	}
}

func TestStartAfterRejectsMalformed(t *testing.T) {
	err := loadValidateErr(t, "bad.yaml", startAfterScenario(twoFlowYAML("noformat")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝格式错误的 start_after,实际通过")
	}
	for _, want := range []string{"start_after", "格式"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsUnknownFlow(t *testing.T) {
	err := loadValidateErr(t, "noflow.yaml", startAfterScenario(twoFlowYAML("ghost.pasv")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝引用未知 flow 的 start_after,实际通过")
	}
	for _, want := range []string{"未知 flow", "ghost"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsUnknownMessage(t *testing.T) {
	err := loadValidateErr(t, "nomsg.yaml", startAfterScenario(twoFlowYAML("control.ghost")))
	if err == nil {
		t.Fatal("期望 Validate 拒绝引用未知 message_id 的 start_after,实际通过")
	}
	for _, want := range []string{"未知 message_id", "ghost"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}

func TestStartAfterRejectsSelfReference(t *testing.T) {
	// flow a 既被自引,又含 message_id pasv(故引用存在),但构成自环。
	body := "link_type: ethernet\nseed: 42\nflows:\n  - name: a\n    start_after: \"a.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "x" }
`
	err := loadValidateErr(t, "self.yaml", body)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 start_after 自引,实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

func TestStartAfterRejectsCycle(t *testing.T) {
	// a.pasv 存在,b.pasv 存在;a 引 b.pasv,b 引 a.pasv → 2-环。
	flowA := "  - name: a\n    start_after: \"b.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "x" }
`
	flowB := "  - name: b\n    start_after: \"a.pasv\"\n    stack:\n" + flowStackYAML + `    messages:
      - from: dst
        message_id: pasv
        stack:
          - payload: { payload: "y" }
`
	err := loadValidateErr(t, "cycle.yaml", "link_type: ethernet\nseed: 42\nflows:\n"+flowA+flowB)
	if err == nil {
		t.Fatal("期望 Validate 拒绝 start_after 2-环,实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

func TestValidateRejectsDuplicateFlowName(t *testing.T) {
	flowA := "  - name: dup\n    stack:\n" + flowStackYAML + `    messages:
      - from: src
        stack:
          - payload: { payload: "a" }
`
	err := loadValidateErr(t, "dupname.yaml", "link_type: ethernet\nseed: 42\nflows:\n"+flowA+flowA)
	if err == nil {
		t.Fatal("期望 Validate 拒绝重复 flow 名,实际通过")
	}
	for _, want := range []string{"dup", "不唯一"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误应包含 %q,得到: %v", want, err)
		}
	}
}
