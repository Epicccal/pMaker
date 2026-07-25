package scenario_test

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖时间类型的解析约束:AbsTime 只接受 ISO8601 绝对时刻、Offset 只接受非负时长,
// 两者由各自类型在解析阶段结构性保证取值合法(见 time.go)。

// TestAbsTimeRejectsOffset: AbsTime 只解析 ISO8601,偏移字符串直接失败(结构性保证)。
func TestAbsTimeRejectsOffset(t *testing.T) {
	a := &scenario.AbsTime{}
	if err := yaml.Unmarshal([]byte("+1s"), a); err == nil {
		t.Fatal("期望 AbsTime 拒绝偏移字符串,实际通过")
	}
}

// TestOffsetRejectsAbsolute: Offset 只解析时长,绝对时刻直接失败(结构性保证)。
func TestOffsetRejectsAbsolute(t *testing.T) {
	o := &scenario.Offset{}
	if err := yaml.Unmarshal([]byte("2024-01-01T00:00:00Z"), o); err == nil {
		t.Fatal("期望 Offset 拒绝绝对时刻字符串,实际通过")
	}
}

// TestOffsetRejectsNegative: Offset 拒绝负时长——负偏移通常意味着 base_time 选错起点,
// 应把 base_time 提前而非用负 offset 够到零点之前(结构性保证)。
func TestOffsetRejectsNegative(t *testing.T) {
	for _, s := range []string{"-1ms", "-1.5s", "-500ms"} {
		o := &scenario.Offset{}
		if err := yaml.Unmarshal([]byte(s), o); err == nil {
			t.Fatalf("期望 Offset 拒绝负时长 %q,实际通过", s)
		}
	}
	// 0 与正值仍应通过。
	for _, s := range []string{"0s", "+0ms", "+1.5s", "500ms"} {
		o := &scenario.Offset{}
		if err := yaml.Unmarshal([]byte(s), o); err != nil {
			t.Fatalf("期望 Offset 接受非负时长 %q,实际失败: %v", s, err)
		}
	}
}
