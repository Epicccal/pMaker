// Package plan 把 scenario 模型编排成带显式时间戳的 PlannedPacket 列表。
//
// standalone packets 与 flows 展开后的包在此汇流,按 Time 稳定排序,再交给 builder
// 序列化、writer 落盘。时间锚为 base_time(ISO8601,缺省=确定性 2020 基准),各 offset_time
// 的参照点因字段而异(见下)。
//
// 时间语义为「相对上一包 + 跨流独立」:
//   - standalone packets:offset_time 相对**上一包**(第一包相对 base);无 offset 则接续默认游标
//     (+1ms)。即每包 = 上一包 + offset(或 +1ms),SYN 扫描等"按间隔发包"场景由此表达。
//   - flows 默认互相独立:flow.offset_time 相对 **base_time**(无 offset 则 = base),**不夹紧、不读
//     packet 游标、不推进它**——无 offset 的多条 flow 在 base 并发(模拟浏览器多连接并行);
//     想顺序就显式给递增 offset。
//   - flow 的 start_after(opt-in):形如 "flow名.message_id",置则该 flow 锚 = 被引消息整组完成
//     时刻(msgCursor)+ offset_time(缺省 0 紧接)。用于"一个 flow 在另一个 flow 某消息完成后
//     开始"(如 FTP 控制通道触发数据通道)。此时 offset_time 的参照点从 base 变为被引 msgCursor。
//     这是**显式跨流依赖**,默认独立性不变;Plan 用两阶段拓扑展开(无 start_after 的先展开并登记
//     msgid→时刻,有 start_after 的多遍解析),循环依赖在校验阶段拦截。
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

	// ② flows:两阶段拓扑展开。
	//   - Phase 1:无 start_after 的 flow,声明序,各自 anchor=base+offset(无 offset 则 base),
	//     互不依赖、可并行(跨流独立)。展开后把具名 flow 的 message_id→完成时刻收入 registry。
	//   - Phase 2:有 start_after 的 flow,多遍依赖序(声明序为平手):被引 flow 已在 registry 中
	//     即可解析 anchor=被引消息 msgCursor + offset_time(缺省 0 紧接),展开并收入自己的 msgid 表
	//     (供后续依赖它的 flow)。被引 flow 可声明在后(前向引用),多遍天然处理。
	//     无 start_after 的 flow 不读/推进 packet 游标。
	registry := map[string]map[string]time.Time{} // flow 名 → message_id → 整组完成时刻
	expandFlow := func(f scenario.FlowSpec, anchorBase time.Time, fi int) error {
		anchor := anchorBase
		if f.OffsetTime != nil {
			anchor = anchorBase.Add(f.OffsetTime.Duration())
		}
		expanded, _, msgids, err := flow.Expand(f, anchor)
		if err != nil {
			return fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		merged = append(merged, expanded...)
		if f.Name != "" {
			registry[f.Name] = msgids
		}
		return nil
	}

	// Phase 1:无 start_after 的 flow,声明序。
	for fi, f := range s.Flows {
		if f.StartAfter != "" {
			continue
		}
		if err := expandFlow(f, base, fi); err != nil {
			return nil, err
		}
	}

	// Phase 2:有 start_after 的 flow,多遍直至全部解析。
	remaining := make([]int, 0, len(s.Flows))
	for fi, f := range s.Flows {
		if f.StartAfter != "" {
			remaining = append(remaining, fi)
		}
	}
	for len(remaining) > 0 {
		progress := false
		// 必须 fresh 分配 next,不能复用 remaining 的底层数组(边迭代边 append 会覆盖未读项)。
		next := make([]int, 0, len(remaining))
		for _, fi := range remaining {
			f := s.Flows[fi]
			refFlow, refMsg, _ := scenario.SplitStartAfter(f.StartAfter)
			// registry[refFlow] 可能为 nil(被引 flow 未具名或未展开);nil 内层 map 读取在 Go 中安全。
			mc, ok := registry[refFlow][refMsg]
			if !ok {
				next = append(next, fi) // 被引 flow 尚未展开,留待下一遍
				continue
			}
			if err := expandFlow(f, mc, fi); err != nil {
				return nil, err
			}
			progress = true
		}
		remaining = next
		if !progress {
			// 防御纵深:正常情况下循环依赖在校验阶段(validateStartAfter)已拦截;若到这说明校验被绕过。
			return nil, fmt.Errorf("start_after 存在未解析的循环依赖(应在校验阶段拦截)")
		}
	}

	// ③ 稳定排序:跨流并发后时间交织,同 Time 保持声明/合并顺序,保证确定性。
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	return merged, nil
}
