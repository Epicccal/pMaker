// Package pipeline 是「已解析场景 → 待落盘包」的共享链路。
//
// CLI(gen/validate)与 MCP(generate_yaml/generate_pcap)此前各自抄一遍
// Validate → Warnings → plan.Plan → builder.BuildPlanned 的调用序列,
// 「链上多一步」类改动须同步两处(20723c8 已踩过一次)。本包把这段收敛成
// 一个入口,两个 cmd 只保留入参解析、输出渲染与产物落盘策略。
//
// 不进本包的部分(各处语义确实不同,统一会改掉行为):
//   - Parse / Load:CLI 走 Load 并在错误上附带文件名,MCP 走 Parse 拿字节;
//   - 软告警的渲染:CLI 打 stderr 文本,MCP 塞进结构化 warnings;
//   - 产物落盘路径与 YAML 归档:MCP 归档失败降级为软告警,CLI 不归档;
//   - 摘要消费方式。
package pipeline

import (
	"fmt"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// Result 是共享链路的产物。
//
// 失败时按阶段填充,便于调用方决定渲染方式:Valid 在校验结束时即确定,
// Warnings 在校验通过后即填充(后续阶段失败也保留,与两个入口原有行为一致),
// Planned/Packets 仅在全程成功时非空。
type Result struct {
	// Valid 表示场景已通过 scenario.Validate(输入合法)。
	// 仅在 Build 返回错误时有区分力:Build 成功时恒为 true,故
	// (err != nil && Valid) 即「输入没问题,是内部故障」,与 (err != nil && !Valid)
	// 的「让调用方改 YAML」相对。MCP 的 Valid/isError 双维度据此分流。
	Valid    bool
	Warnings []scenario.Diagnostic
	Planned  []scenario.PlannedPacket
	Packets  []builder.OutPacket
}

// Check 校验场景并收集软告警,不构包(generate_yaml / CLI validate 用)。
// 校验失败返回 nil + 错误;通过则返回软告警(可能为空)。
func Check(s *scenario.Scenario) ([]scenario.Diagnostic, error) {
	if err := scenario.Validate(s); err != nil {
		return nil, err
	}
	return scenario.Warnings(s), nil
}

// Build 在 Check 之上继续时间编排与构包。
//
// 阶段前缀("时间编排:" / "构包:")在此统一附带:同一故障在 CLI 与 MCP 下文案一致,
// 且两个入口不必各自维护前缀表。写盘不在本包内(输出路径策略各入口不同),
// "写盘:" 前缀仍由调用方附。
//
// 已知有多条下游硬错已被 Validate 提前拦截(TFTP 块号上限、空 message.stack 等),
// 校验路径下到不了这些分支;前缀仍按前缀表维护,供其余执行层故障与防御纵深使用。
func Build(s *scenario.Scenario) (Result, error) {
	var r Result

	ws, err := Check(s)
	if err != nil {
		return r, err
	}
	r.Valid = true
	r.Warnings = ws

	// packets 与 flows 汇流成带显式时间戳的 PlannedPacket,按时间排序后再构建。
	planned, err := plan.Plan(s)
	if err != nil {
		return r, fmt.Errorf("时间编排: %w", err)
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		return r, fmt.Errorf("构包: %w", err)
	}

	r.Planned = planned
	r.Packets = pkts
	return r, nil
}
