// Package plan 把 scenario 模型编排成带显式时间戳的 PlannedPacket 列表。
//
// standalone packets 与 flows 展开后的包在此汇流,按 Time 稳定排序,再交给 builder
// 序列化、writer 落盘。时间分配策略:
//   - 显式定时(packet.time / flow.start / base_time)按用户指定值放置,不推进默认游标;
//   - 未显式定时的包从 base_time 起每 1ms 一个,接续默认序列——与旧 builder 内建时间
//     分配等价,保证现有 golden pcap 逐字节不变。
//
// 全程不使用 time.Now(),base_time 缺省为确定性 2020 基准,输出可复现。
package plan

import (
	"fmt"
	"sort"
	"time"

	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// DefaultBaseTime 是未指定 base_time 时的确定性基准(不使用 time.Now)。
// 与历史 builder 内建基准保持一致,以保证 golden 不变。
var DefaultBaseTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// defaultStep 是未显式定时的相邻包之间的默认时间间隔。
const defaultStep = time.Millisecond

// Plan 把场景里的 packets 与 flows 汇流成按时间排序的 PlannedPacket 列表。
func Plan(s *scenario.Scenario) ([]scenario.PlannedPacket, error) {
	base := DefaultBaseTime
	if s.BaseTime != nil {
		base = s.BaseTime.Resolve(DefaultBaseTime)
	}

	merged := make([]scenario.PlannedPacket, 0, len(s.Packets))
	cursor := base // 默认序列游标:未显式定时的包从此递增 defaultStep

	// ① standalone packets(声明序)。
	for _, p := range s.Packets {
		var t time.Time
		if p.Time != nil {
			t = p.Time.Resolve(base) // 显式:不推进默认游标
		} else {
			t = cursor
			cursor = cursor.Add(defaultStep)
		}
		merged = append(merged, scenario.PlannedPacket{Packet: p, Time: t})
	}

	// ② flows(声明序):flow.Expand 产出 stack 包,再分配时间。
	for fi, f := range s.Flows {
		expanded, err := flow.Expand(f)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		anchor, hasStart := base, false
		if f.Start != nil {
			anchor, hasStart = f.Start.Resolve(base), true
		}
		for i, ep := range expanded {
			var t time.Time
			if hasStart {
				// 流锚定到 base+start,流内每包 defaultStep 间隔,不干扰默认游标。
				t = anchor.Add(time.Duration(i) * defaultStep)
			} else {
				t = cursor
				cursor = cursor.Add(defaultStep) // 接续默认序列
			}
			merged = append(merged, scenario.PlannedPacket{Packet: ep, Time: t})
		}
	}

	// ③ 稳定排序:同 Time 保持声明/合并顺序,保证确定性。
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	return merged, nil
}
