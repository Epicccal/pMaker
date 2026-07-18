// Package plan 把 scenario 模型编排成带显式时间戳的 PlannedPacket 列表。
//
// standalone packets 与 flows 展开后的包在此汇流,按 Time 稳定排序,再交给 builder
// 序列化、writer 落盘。时间模型统一为「base_time + offset_time」:
//   - base_time 是唯一的绝对锚(ISO8601,缺省=确定性 2020 基准);
//   - packet.offset_time / flow.offset_time 是相对 base_time 的时长偏移,
//     显式给出时按 base+offset 放置、不推进默认游标;
//   - 未显式定时的包从 base_time 起每 1ms 一个,接续默认序列——与旧 builder 内建
//     时间分配等价,保证现有 golden pcap 逐字节不变。
//
// 全程不使用 time.Now(),输出可复现。
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

// Plan 把场景里的 packets 与 flows 汇流成按时间排序的 PlannedPacket 列表。
func Plan(s *scenario.Scenario) ([]scenario.PlannedPacket, error) {
	// base_time 是唯一绝对锚;AbsTime 类型已保证它只能是 ISO8601 绝对时刻。
	base := DefaultBaseTime
	if s.BaseTime != nil {
		base = s.BaseTime.Time()
	}

	// 预估容量:standalone packets + 每条 flow 的粗略包数(握手3 + 消息段 + 挥手4 ≈ 8 起步)。
	merged := make([]scenario.PlannedPacket, 0, len(s.Packets)+len(s.Flows)*8)
	cursor := base // 默认序列游标:未显式定时的包从此递进 flow.DefaultStep

	// ① standalone packets(声明序)。
	for _, p := range s.Packets {
		var t time.Time
		if p.OffsetTime != nil {
			t = base.Add(p.OffsetTime.Duration()) // 显式:base+offset,不推进默认游标
		} else {
			t = cursor
			cursor = cursor.Add(flow.DefaultStep)
		}
		merged = append(merged, scenario.PlannedPacket{Packet: p, Time: t})
	}

	// ② flows(声明序):flow.Expand 自管时间轴,产出带时间戳的 PlannedPacket;plan 只汇流。
	for fi, f := range s.Flows {
		var anchor time.Time
		if f.OffsetTime != nil {
			anchor = base.Add(f.OffsetTime.Duration()) // 显式:流锚 = base+offset,不推进默认游标
		} else {
			anchor = cursor // 缺省:接续默认序列
		}
		expanded, err := flow.Expand(f, anchor)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		merged = append(merged, expanded...)
		// 缺省(无 offset)的流推进默认游标到流末包之后,保持后续 standalone/flow 接续。
		if f.OffsetTime == nil && len(expanded) > 0 {
			cursor = expanded[len(expanded)-1].Time.Add(flow.DefaultStep)
		}
	}

	// ③ 稳定排序:同 Time 保持声明/合并顺序,保证确定性。
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	return merged, nil
}
