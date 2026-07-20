// Package plan 把 scenario 模型编排成带显式时间戳的 PlannedPacket 列表。
//
// standalone packets 与 flows 展开后的包在此汇流,按 Time 稳定排序,再交给 builder
// 序列化、writer 落盘。时间锚为 base_time(ISO8601,缺省=确定性 2020 基准),各 offset_time
// 的参照点因字段而异(见下)。
//
// 时间语义为「相对上一包 + 跨流独立」:
//   - standalone packets:offset_time 相对**上一包**(第一包相对 base);无 offset 则接续默认游标
//     (+1ms)。即每包 = 上一包 + offset(或 +1ms),SYN 扫描等"按间隔发包"场景由此表达。
//   - flows 互相独立:flow.offset_time 相对 **base_time**(无 offset 则 = base),**不夹紧、不读
//     packet 游标、不推进它**——无 offset 的多条 flow 在 base 并发(模拟浏览器多连接并行);
//     想顺序就显式给递增 offset。
//   - flow 内部由 flow.Expand 自管时间轴:message.offset_time 相对**上一条消息**(第一条相对
//     握手完成后),链式 delta、天然单调(见 internal/flow)。
//
// 跨流并发后包时间会交织,故用稳定排序保证同 Time 保持声明/合并顺序,输出可复现。
// 全程不使用 time.Now()。
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
//
// 以函数暴露:time.Date 不能做 const,而可变 var 是可被全局赋值篡改的共享状态,
// 会破坏"同一 scenario+seed 逐字节相同"的确定性。函数每次返回同一时刻,不可被
// 外部赋值。
func DefaultBaseTime() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }

// Plan 把场景里的 packets 与 flows 汇流成按时间排序的 PlannedPacket 列表。
func Plan(s *scenario.Scenario) ([]scenario.PlannedPacket, error) {
	// base_time 是唯一绝对锚;AbsTime 类型已保证它只能是 ISO8601 绝对时刻。
	base := DefaultBaseTime()
	if s.BaseTime != nil {
		base = s.BaseTime.Time()
	}

	// 预估容量:standalone packets + 每条 flow 的粗略包数(握手3 + 消息段 + 挥手4 ≈ 8 起步)。
	merged := make([]scenario.PlannedPacket, 0, len(s.Packets)+len(s.Flows)*8)
	// cursor 是无 offset 包的接续游标(默认间隔 DefaultStep);prevT 是上一包的实际时刻。
	// 二者都只服务 packets;flows 互不依赖、不消费它们。
	cursor := base
	prevT := base // 第一包的"上一包"= base

	// ① standalone packets(声明序):offset_time 相对上一包——有 offset 则 t=prevT+offset,
	// 无 offset 则接续 cursor(默认 +1ms);之后 cursor/prevT 始终推进。offset>=0 故天然单调。
	for _, p := range s.Packets {
		t := cursor
		if p.OffsetTime != nil {
			t = prevT.Add(p.OffsetTime.Duration()) // 相对上一包(第一包相对 base)
		}
		merged = append(merged, scenario.PlannedPacket{Packet: p, Time: t})
		cursor = t.Add(flow.DefaultStep) // 无 offset 的下一包接在本包之后 +1ms
		prevT = t                        // 下一包的"上一包"= 本包
	}

	// ② flows(声明序):每条 flow 独立——anchor=base+flow.offset_time(无 offset 则 = base),
	// 不夹紧、不读 cursor、不推进 cursor。无 offset 的多条 flow 在 base 并发。
	for fi, f := range s.Flows {
		anchor := base
		if f.OffsetTime != nil {
			anchor = base.Add(f.OffsetTime.Duration())
		}
		expanded, _, err := flow.Expand(f, anchor)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		merged = append(merged, expanded...)
	}

	// ③ 稳定排序:跨流并发后时间交织,同 Time 保持声明/合并顺序,保证确定性。
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	return merged, nil
}
