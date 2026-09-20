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
//     在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发数据通道)。
//   - message 级 start_after(同形):某条消息的起点锚到被引时刻而非默认的"上一条消息末尾",实现
//     "某条消息在另一个 flow / 另一个 flow 某消息完成后才开始"(如控制通道的 226 等数据通道传完再发)。
//     禁止同流自引;流内顺序由 message 链式游标保证。
//
// 展开分两段(方案 B,支持消息级双向交错的 start_after):
//   - 阶段一(算时):按事件粒度的拓扑序逐个算出每个事件的绝对时刻(flowStart / 各 message 的
//     start 与 msgCursor / flowEnd),不发包。被引事件先算出,引用方后算——FTP 式 control.150 →
//     data → control.226 这种交错在事件粒度是有向无环的(Validate 已检环),故能算通,而不会被
//     "整流粒度互等对方先完成"的死锁卡住(见 scheduler)。
//   - 阶段二(展开):各 flow 拿着已算好的 per-message 起始时刻表独立发包(flow.Expand),seq/ack
//     状态在单次展开内连续维护。plan 按 Time 稳定排序输出。
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
// 会破坏"同一 scenario 逐字节相同"的确定性。函数每次返回同一时刻,不可被
// 外部赋值。
func DefaultBaseTime() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }

// scheduler 是阶段一(算时):按事件粒度递归+记忆化算出每个事件的绝对时刻,不发包。
//
// 事件粒度比 flow 粒度更细:flowStart、每条 message 的 start/msgCursor、flowEnd 都是独立事件,
// 各自只依赖其引用的事件。这使得 FTP 式双向交错(control.226 依赖 data.flowEnd、data.flowStart
// 依赖 control.pasv)能算通——前者(early 的 control.pasv)先算出,后者(late 的 control.226)
// 等前者算完再算;而整流粒度会把 control 与 data 压成互等对方整流先完成的死锁。
//
// 真环(跨流消息级互引)由 Validate 的事件图三色 DFS 拦截,不会走到这里;scheduler 自带
// in-flight 守卫作为防御纵深,环出现时返回"循环依赖"错误而非无限递归。
type scheduler struct {
	flows    []scenario.FlowSpec
	base     time.Time
	profiles []flow.Profile // 每条 flow 一次 ProfileOf,算时统一取时间形状(与 Expand 同源)

	fstart   map[int]time.Time    // flowStart(fi)
	mend     map[[2]int]time.Time // message(fi,j) 的整组末尾(msgCursor)
	fend     map[int]time.Time    // flowEnd(fi)
	inflight map[string]bool      // 正在计算中的节点(环检测防御)
	path     []string             // 当前递归路径,用于环报错
}

// newScheduler 构造阶段一算时器。base 为场景绝对锚(DefaultBaseTime 或 s.BaseTime)。
func newScheduler(flows []scenario.FlowSpec, base time.Time) *scheduler {
	profiles := make([]flow.Profile, len(flows))
	for i, f := range flows {
		profiles[i] = flow.ProfileOf(f.Stack)
	}
	return &scheduler{
		flows:    flows,
		base:     base,
		profiles: profiles,
		fstart:   map[int]time.Time{},
		mend:     map[[2]int]time.Time{},
		fend:     map[int]time.Time{},
		inflight: map[string]bool{},
	}
}

// nodeKey 是 in-flight 守卫与路径用的节点标识。
func nodeKey(kind string, fi, j int) string {
	if j < 0 {
		return fmt.Sprintf("%s:%d", kind, fi)
	}
	return fmt.Sprintf("%s:%d:%d", kind, fi, j)
}

// flowStart 算 flow fi 的起点(锚):无 flow 级 start_after = base + offset;有则 = 被引时刻 + offset。
func (sc *scheduler) flowStart(fi int) (time.Time, error) {
	if t, ok := sc.fstart[fi]; ok {
		return t, nil
	}
	k := nodeKey("fstart", fi, -1)
	if sc.inflight[k] {
		return time.Time{}, sc.cycleErr(k)
	}
	sc.inflight[k] = true
	sc.path = append(sc.path, "flow:"+sc.flowLabel(fi))

	f := sc.flows[fi]
	t := sc.base
	if f.StartAfter != "" {
		ref, err := sc.resolveRef(f.StartAfter)
		if err != nil {
			return time.Time{}, err
		}
		t = ref
	}
	if f.OffsetTime != nil {
		t = t.Add(f.OffsetTime.Duration())
	}
	sc.fstart[fi] = t
	delete(sc.inflight, k)
	sc.path = sc.path[:len(sc.path)-1]
	return t, nil
}

// msgStart 算 flow fi 第 j 条消息的起始时刻:
//   - message 级 start_after:被引时刻 + offset_time(缺省 0 紧接)。
//   - 否则首条( j==0)= flowStart + 握手步数;后续 = 上一条 msgCursor + offset_time。
func (sc *scheduler) msgStart(fi, j int) (time.Time, error) {
	f := sc.flows[fi]
	m := f.Messages[j]
	var t time.Time
	if m.StartAfter != "" {
		ref, err := sc.resolveRef(m.StartAfter)
		if err != nil {
			return time.Time{}, err
		}
		t = ref
	} else if j == 0 {
		fs, err := sc.flowStart(fi)
		if err != nil {
			return time.Time{}, err
		}
		t = fs.Add(time.Duration(sc.profiles[fi].HandshakeSteps) * flow.DefaultStep)
	} else {
		prev, err := sc.msgEnd(fi, j-1)
		if err != nil {
			return time.Time{}, err
		}
		t = prev
	}
	if m.OffsetTime != nil {
		t = t.Add(m.OffsetTime.Duration())
	}
	return t, nil
}

// msgEnd 算 flow fi 第 j 条消息的整组末尾(msgCursor)= start + MessageDuration。
// MessageDuration 与 flow.Expand 的"一条消息占多久"同源(见 flow.messagePlan),保证算时
// 与发包对 msgCursor 的认知一致——这是跨流 start_after 锚点精确对齐的前提。
func (sc *scheduler) msgEnd(fi, j int) (time.Time, error) {
	key := [2]int{fi, j}
	if t, ok := sc.mend[key]; ok {
		return t, nil
	}
	k := nodeKey("mend", fi, j)
	if sc.inflight[k] {
		return time.Time{}, sc.cycleErr(k)
	}
	sc.inflight[k] = true
	sc.path = append(sc.path, fmt.Sprintf("msg:%s#%d", sc.flowLabel(fi), j))

	start, err := sc.msgStart(fi, j)
	if err != nil {
		return time.Time{}, err
	}
	dur, err := flow.MessageDuration(sc.flows[fi].Messages[j], sc.profiles[fi])
	if err != nil {
		return time.Time{}, err
	}
	end := start.Add(dur)
	sc.mend[key] = end
	delete(sc.inflight, k)
	sc.path = sc.path[:len(sc.path)-1]
	return end, nil
}

// flowEnd 算 flow fi 的整流结束时刻(挥手后)= 末条消息 msgCursor + 关闭步数
// (无消息则 = flowStart + 握手步数 + 关闭步数)。供裸 flow 名引用。
func (sc *scheduler) flowEnd(fi int) (time.Time, error) {
	if t, ok := sc.fend[fi]; ok {
		return t, nil
	}
	k := nodeKey("fend", fi, -1)
	if sc.inflight[k] {
		return time.Time{}, sc.cycleErr(k)
	}
	sc.inflight[k] = true
	sc.path = append(sc.path, "end:"+sc.flowLabel(fi))

	f := sc.flows[fi]
	var lastEnd time.Time
	if len(f.Messages) == 0 {
		fs, err := sc.flowStart(fi)
		if err != nil {
			return time.Time{}, err
		}
		lastEnd = fs.Add(time.Duration(sc.profiles[fi].HandshakeSteps) * flow.DefaultStep)
	} else {
		le, err := sc.msgEnd(fi, len(f.Messages)-1)
		if err != nil {
			return time.Time{}, err
		}
		lastEnd = le
	}
	fe := lastEnd.Add(time.Duration(sc.profiles[fi].CloseSteps) * flow.DefaultStep)
	sc.fend[fi] = fe
	delete(sc.inflight, k)
	sc.path = sc.path[:len(sc.path)-1]
	return fe, nil
}

// resolveRef 解析 start_after 引用为被引事件的绝对时刻:裸 flow 名 → flowEnd;
// "flow名.message_id" → 该消息 msgCursor。被引 flow/message 的存在性已由 Validate 校验,
// 此处仅查表;若引用格式非法或查无(校验被绕过)则报错。
func (sc *scheduler) resolveRef(ref string) (time.Time, error) {
	refFlow, refMsg, ok := scenario.SplitStartAfter(ref)
	if !ok {
		return time.Time{}, fmt.Errorf("start_after %q 格式应为 \"flow名\" 或 \"flow名.message_id\"", ref)
	}
	fi := sc.flowIndex(refFlow)
	if fi < 0 {
		return time.Time{}, fmt.Errorf("start_after 引用未知 flow %q", refFlow)
	}
	if refMsg == "" {
		return sc.flowEnd(fi)
	}
	j := sc.msgIndexByID(fi, refMsg)
	if j < 0 {
		return time.Time{}, fmt.Errorf("start_after 引用 flow %q 中未知 message_id %q", refFlow, refMsg)
	}
	return sc.msgEnd(fi, j)
}

func (sc *scheduler) flowIndex(name string) int {
	for i, f := range sc.flows {
		if name != "" && f.Name == name {
			return i
		}
	}
	return -1
}

func (sc *scheduler) msgIndexByID(fi int, id string) int {
	for j, m := range sc.flows[fi].Messages {
		if m.MessageID == id {
			return j
		}
	}
	return -1
}

func (sc *scheduler) flowLabel(fi int) string {
	if n := sc.flows[fi].Name; n != "" {
		return n
	}
	return fmt.Sprintf("#%d", fi)
}

// cycleErr 是防御纵深:真环由 Validate 拦截,走到这说明 Plan 被直接调用在循环场景上。
func (sc *scheduler) cycleErr(k string) error {
	return fmt.Errorf("start_after 循环依赖(应在校验阶段拦截): %s", k)
}

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

	// ⓪ tftp_transfer 宏展开:在算时之前把宏消息降解成普通 tftp 消息,使阶段一与阶段二
	//   看到同一组消息,start_after 锚点才能对齐。
	//   宏的字段/位置合法性由 scenario.Validate 提前拦截,这里只做展开与块号上限检查。
	flows, err := flow.ExpandTFTPTransfers(s.Flows)
	if err != nil {
		return nil, err
	}

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

	// ② 阶段一(算时):按事件粒度递归算出每条 flow 各 message 的起始时刻与整流结束时刻。
	//   真环由 Validate 拦截;scheduler 的 in-flight 守卫是防御纵深,环出现时报错而非死循环。
	sc := newScheduler(flows, base)

	// ③ 阶段二(展开):各 flow 拿着已算好的 per-message 起始时刻表独立发包。按声明序展开,
	//   保证同 Time 的包保持声明/合并顺序(稳定排序确定性);跨流依赖已在阶段一解算为绝对时刻,
	//   故不再需要"被引 flow 先整流展开"——这正是整流粒度死锁被解开的要害。
	for fi, f := range flows {
		anchor, err := sc.flowStart(fi)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		sched := make([]flow.MessageSchedule, len(f.Messages))
		for j := range f.Messages {
			st, err := sc.msgStart(fi, j)
			if err != nil {
				return nil, fmt.Errorf("flow[%d](%s) message[%d]: %w", fi, f.Name, j, err)
			}
			sched[j] = flow.MessageSchedule{Start: st}
		}
		expanded, _, _, err := flow.Expand(f, anchor, sched)
		if err != nil {
			return nil, fmt.Errorf("flow[%d](%s): %w", fi, f.Name, err)
		}
		merged = append(merged, expanded...)
	}

	// ④ 稳定排序:跨流并发后时间交织,同 Time 保持声明/合并顺序,保证确定性。
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	return merged, nil
}
