package pipeline_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/pipeline"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// validScenario 是最小可生成场景(eth/ipv4/tcp SYN)。
func validScenario() *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
			},
		}},
	}
}

// TestBuildValid:合法场景 Valid=true 且产出包。
func TestBuildValid(t *testing.T) {
	res, err := pipeline.Build(validScenario())
	if err != nil {
		t.Fatalf("合法场景不应报错: %v", err)
	}
	if !res.Valid {
		t.Error("合法场景 Valid 应为 true")
	}
	if len(res.Packets) == 0 {
		t.Error("应产出至少一个包")
	}
	if len(res.Planned) != len(res.Packets) {
		t.Errorf("未分片时 Planned 与 Packets 应等长: %d vs %d", len(res.Planned), len(res.Packets))
	}
}

// TestBuildInvalid:校验失败 Valid=false,错误不带阶段前缀(是校验原话,不是执行层故障)。
func TestBuildInvalid(t *testing.T) {
	s := validScenario()
	s.Packets[0].Stack[2] = scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{}} // 缺 sport/dport

	res, err := pipeline.Build(s)
	if err == nil {
		t.Fatal("缺 sport/dport 应报错")
	}
	if res.Valid {
		t.Error("校验失败时 Valid 应为 false")
	}
	if len(res.Packets) != 0 {
		t.Error("校验失败不应产出包")
	}
	// 阶段前缀只加在执行层(pipeline.Build 的 Plan/BuildPlanned),"时间编排:"/"构包:"
	// 不应出现在校验错误上——MCP 靠这个区分「改 YAML」与「内部故障」。
	for _, prefix := range []string{"时间编排:", "构包:"} {
		if strings.HasPrefix(err.Error(), prefix) {
			t.Errorf("校验错误不应带执行层前缀 %q: %v", prefix, err)
		}
	}
}

// TestCheckCollectsWarnings:Check 只校验不构包,并带回软告警。
// mtu=40 低于 RFC 791 下限 68,触发 ipv4.mtu-below-minimum(软告警,照常分片)。
func TestCheckCollectsWarnings(t *testing.T) {
	s := validScenario()
	s.Packets[0].Stack[1] = scenario.Layer{
		Type:   "ipv4",
		Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 40},
	}

	ws, err := pipeline.Check(s)
	if err != nil {
		t.Fatalf("小 mtu 是软告警不是硬错: %v", err)
	}
	var found bool
	for _, w := range ws {
		if w.Code == scenario.CodeIPv4MTUBelowMinimum {
			found = true
		}
	}
	if !found {
		t.Errorf("应带回 %s,得到 %v", scenario.CodeIPv4MTUBelowMinimum, ws)
	}
}
