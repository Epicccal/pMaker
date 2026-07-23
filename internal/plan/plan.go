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
//   - flow 的 start_after(opt-in):形如 "flow名"(该 flow 整流结束,挥手后)或 "flow名.message_id"
//     (该消息整组完成,msgCursor);置则该 flow 锚 = 被引时刻 + offset_time(缺省 0 紧接)。用于"一个 flow
//     在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发数据通道)。这是**显式跨流依赖**,
//     默认独立性不变;Plan 用多遍拓扑展开(被引 flow 先展开并登记时刻,引用方多遍解析),循环依赖在校验阶段拦截。
//   - message 级 start_after(同形 "flow名" 或 "flow名.message_id"):某条消息的起点锚到被引时刻而非
//     默认的"上一条消息末尾",实现"某条消息在另一个 flow / 另一个 flow 某消息完成后才开始"(如控制通道触发本
//     flow 某条迟到请求)。message 级只读被引时刻,不改变 flow 自身的 anchor;禁止同流自引。同一 flow 内多条
//     message 可各自 start_after 不同被引 flow,该 flow 整体视作依赖这些被引 flow(建边 = f.Name → refFlow)。
//     Plan 展开该 flow 时把 resolve 回调注入 Expand:resolve 从已展开 flow 的 registry(整流结束时刻与 msgCursor)
//     查被引时刻;被引 flow 须先于引用方展开,多遍拓扑天然处理。
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

// resolvedT 记录一个已展开具名 flow 的时刻:整流结束(挥手后,供裸 flow 名引用)与
// message_id→msgCursor(供 "flow名.message_id" 引用)。flow 级与 message 级 start_after 共用。
type resolvedT struct {
	flowEnd    time.Time
	msgCursors map[string]time.Time
}

// Plan 把场景里的 packets 与 flows 汇流成按时间排序的 PlannedPacket 列表。
func Plan(s *scenario.Scenario) ([]scenario.PlannedPacket, error) {
	// base_time 是唯一绝对锚;AbsTime 类型已保证它只能是 ISO8601 绝对时刻。
	base := DefaultBaseTime()
	if s.BaseTime != nil {
		base = s.BaseTime.Time()
	}

	// resolvedT 见包级定义。registry 记录已展开具名 flow 的两类时刻(整流结束 / msgCursor)。
	registry := map[string]resolvedT{}
	// resolve 从 registry 查被引时刻:裸 flow 名 → flowEnd;带 msg → msgCursor。
	// 闭包捕获 registry(共享可变),随展开推进,被引 flow 入表后即可命中。
	resolve := func(refFlow, refMsg string) (time.Time, bool) {
		r, ok := registry[refFlow]
		if !ok {
			return time.Time{}, false
		}
		if refMsg == "" {
			return r.flowEnd, true
		}
		t, ok := r.msgCursors[refMsg]
		return t, ok
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

	// ② flows:多遍拓扑展开。
	//   - registry 记录每个已展开具名 flow 的两类时刻:整流结束(挥手后,供裸 flow 名引用)与
	//     message_id→msgCursor(供 "flow名.message_id" 引用)。flow 级与 message 级 start_after 共用。
	//   - 每遍按声明序扫剩余 flow,凡其所有被引 flow(flow 级 start_after 的被引 flow + 各 message 级
	//     start_after 的被引 flow)均已展开入 registry 即可展开;否则留待下一遍。声明序为平手,被引 flow
	//     可声明在后(前向引用)。被引时刻通过 resolve 回调注入 Expand:裸 flow 名取 flowEnd,带 msg 取
	//     msgCursor。无 start_after 的 flow 不读/推进 packet 游标(跨流独立)。
	//   - 循环依赖正常由 validateStartAfter 在校验阶段拦截;此处的 no-progress 是防御纵深。
	expandFlow := func(f scenario.FlowSpec, fi int) error {
		// flow 锚基准:无 start_after = base;有则 = 被引时刻(此时被引 flow 必已展开,resolve 必命中)。
		anchorBase := base
		if f.StartAfter != "" {
			refFlow, refMsg, _ := scenario.SplitStartAfter(f.StartAfter)
			got, ok := resolve(refFlow, refMsg)
			if !ok {
				// canExpand 已保证被引 flow 入表;到此处说明校验被绕过(如被引 message_id 不存在)。
				return fmt.Errorf("flow[%d](%s): start_after %q 被引 flow/message 未展开", fi, f.Name, f.StartAfter)
			}
			anchorBase = got
		}
		anchor := anchorBase
		if f.OffsetTime != nil {
			anchor = anchorBase.Add(f.OffsetTime.Duration())
		}
		expanded, flowEnd, msgids, err := flow.Expand(f, anchor, resolve)
		if err != nil {
			return fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		merged = append(merged, expanded...)
		if f.Name != "" {
			registry[f.Name] = resolvedT{flowEnd: flowEnd, msgCursors: msgids}
		}
		return nil
	}

	// 多遍直至全部展开。
	remaining := make([]int, 0, len(s.Flows))
	for fi := range s.Flows {
		remaining = append(remaining, fi)
	}
	for len(remaining) > 0 {
		progress := false
		// 必须 fresh 分配 next,不能复用 remaining 的底层数组(边迭代边 append 会覆盖未读项)。
		next := make([]int, 0, len(remaining))
		for _, fi := range remaining {
			f := s.Flows[fi]
			if !flowDepsResolved(f, registry) {
				next = append(next, fi) // 有被引 flow 尚未展开,留待下一遍
				continue
			}
			if err := expandFlow(f, fi); err != nil {
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

// flowDepsResolved 判断 flow f 的所有 start_after 被引 flow 是否均已展开入 registry。
// 既看 flow 级 start_after,也看各 message 级 start_after;裸 flow 名引用需被引 flow 的 flowEnd
// 已入表(被引 flow 具名才会入表),带 msg 引用需对应 msgCursor 已入表。
func flowDepsResolved(f scenario.FlowSpec, registry map[string]resolvedT) bool {
	check := func(ref string) bool {
		refFlow, refMsg, ok := scenario.SplitStartAfter(ref)
		if !ok {
			return false
		}
		r, ok := registry[refFlow]
		if !ok {
			return false
		}
		if refMsg == "" {
			return !r.flowEnd.IsZero()
		}
		t, ok := r.msgCursors[refMsg]
		return ok && !t.IsZero()
	}
	if f.StartAfter != "" && !check(f.StartAfter) {
		return false
	}
	for _, m := range f.Messages {
		if m.StartAfter != "" && !check(m.StartAfter) {
			return false
		}
	}
	return true
}
