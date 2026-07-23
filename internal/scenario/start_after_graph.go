package scenario

import (
	"fmt"
	"strings"
)

// StartAfterNode 是事件粒度依赖图的一个节点(方案 A/B 共用)。节点代表一个"事件":
// flow 的起点 / 终点,或一条参与 start_after 的 message。ID 为该节点在图中的稳定序号,
// 仅供内部索引;对外含义由 Kind 与 Label 表达。
type StartAfterNode struct {
	Kind  NodeKind
	Flow  int    // 所属 flow 的声明序号
	Msg   int    // Kind==NodeMsg 时为该消息在 flow 内的序号;否则为 -1
	Label string // 可读标签,如 "start:control" / "msg:control.pasv" / "end:data"
}

// NodeKind 枚举事件节点的种类。
type NodeKind int

const (
	NodeStart NodeKind = iota // flow 起点(flowStart)
	NodeEnd                   // flow 终点(flowEnd,挥手后)
	NodeMsg                   // 一条参与引用的 message(带 start_after 或 msgid 被引)
)

// StartAfterGraph 是事件粒度的有向依赖图:边 X→Y 表示"X 依赖 Y(X 在 Y 之后发生)"。
// validateStartAfter 用它做三色 DFS 检环;plan 阶段一(算时)消费它的拓扑序逐事件算时刻。
// 两个关注点共用同一张图,避免在两个包里重复实现图逻辑。
type StartAfterGraph struct {
	Nodes []StartAfterNode
	// Adj[i] 为节点 i 依赖的节点集(X→Y:X 在 Y 之后)。
	Adj [][]int
	key map[string]int // label -> 节点序号(去重)
}

// BuildStartAfterGraph 按 validateStartAfter 的事件粒度规则构建依赖图。
// flows 应已通过基本字段校验(名唯一、引用的 flow/message 存在)。返回的图:
//   - 为每条"参与引用"的 flow(flow 级 start_after、含 message 级 start_after、或被别的 flow
//     引用)建 start / end 节点,并为其中"参与"的消息(带 start_after 或 msgid 被引)建 msg 节点。
//   - 连流内链:首个参与消息依赖 flowStart;相邻参与消息前后依赖;flowEnd 依赖末个参与消息
//     (无参与消息则依赖 flowStart)。跨过非参与消息连相邻参与消息仍是真实"之后"。
//   - 连 start_after 边:引用方节点(flowStart 或某 msg)依赖被引方节点(flowEnd 或某 msg)。
//
// 该图仅供检环与算时;它**有意省略非参与消息**(它们的时间在 plan 算时阶段按流内链式游标
// 另行推进,不影响依赖结构)。返回的边方向为"X 依赖 Y";检环时回边即环。
func BuildStartAfterGraph(flows []FlowSpec) *StartAfterGraph {
	g := &StartAfterGraph{key: map[string]int{}}
	add := func(label string, kind NodeKind, fi, j int) int {
		if i, ok := g.key[label]; ok {
			return i
		}
		i := len(g.Nodes)
		g.Nodes = append(g.Nodes, StartAfterNode{Kind: kind, Flow: fi, Msg: j, Label: label})
		g.Adj = append(g.Adj, nil)
		g.key[label] = i
		return i
	}

	nameCount := flowNameCounts(flows)
	_ = nameCount // 基本校验(被引 flow 唯一、被引 message 存在)由 validateStartAfter 先行

	// 收集 start_after 引用边与被引目标。
	type refEdge struct {
		flowLevel bool
		fi        int
		msgIdx    int
		refFlow   string
		refMsg    string
	}
	bareRef := map[string]bool{}
	msgRef := map[string]map[string]bool{}
	var refs []refEdge
	collectTarget := func(ref string) {
		refFlow, refMsg, ok := SplitStartAfter(ref)
		if !ok {
			return
		}
		if refMsg == "" {
			bareRef[refFlow] = true
			return
		}
		if msgRef[refFlow] == nil {
			msgRef[refFlow] = map[string]bool{}
		}
		msgRef[refFlow][refMsg] = true
	}
	for fi, f := range flows {
		if f.StartAfter != "" {
			refFlow, refMsg, ok := SplitStartAfter(f.StartAfter)
			if !ok {
				continue
			}
			refs = append(refs, refEdge{flowLevel: true, fi: fi, refFlow: refFlow, refMsg: refMsg})
			collectTarget(f.StartAfter)
		}
		for j, m := range f.Messages {
			if m.StartAfter == "" {
				continue
			}
			refFlow, refMsg, ok := SplitStartAfter(m.StartAfter)
			if !ok {
				continue
			}
			refs = append(refs, refEdge{flowLevel: false, fi: fi, msgIdx: j, refFlow: refFlow, refMsg: refMsg})
			collectTarget(m.StartAfter)
		}
	}

	// 定参与 flow(引用方 或 被引方)。
	active := make([]bool, len(flows))
	for fi, f := range flows {
		if f.StartAfter != "" {
			active[fi] = true
		}
		for _, m := range f.Messages {
			if m.StartAfter != "" {
				active[fi] = true
			}
		}
		if f.Name != "" && (bareRef[f.Name] || len(msgRef[f.Name]) > 0) {
			active[fi] = true
		}
	}

	startNode := map[int]int{}
	endNode := map[int]int{}
	msgNodeByPos := map[[2]int]int{}
	msgNodeByName := map[string]map[string]int{}
	for fi, f := range flows {
		if !active[fi] {
			continue
		}
		label := f.Name
		if label == "" {
			label = fmt.Sprintf("#%d", fi)
		}
		s := add("start:"+label, NodeStart, fi, -1)
		e := add("end:"+label, NodeEnd, fi, -1)
		startNode[fi] = s
		endNode[fi] = e

		var parts []int
		for j, m := range f.Messages {
			refBy := f.Name != "" && msgRef[f.Name] != nil && msgRef[f.Name][m.MessageID]
			if m.StartAfter == "" && !refBy {
				continue
			}
			mlabel := fmt.Sprintf("msg:%s#%d", label, j)
			if m.MessageID != "" {
				mlabel = "msg:" + label + "." + m.MessageID
			}
			n := add(mlabel, NodeMsg, fi, j)
			msgNodeByPos[[2]int{fi, j}] = n
			if m.MessageID != "" && f.Name != "" {
				if msgNodeByName[f.Name] == nil {
					msgNodeByName[f.Name] = map[string]int{}
				}
				msgNodeByName[f.Name][m.MessageID] = n
			}
			parts = append(parts, n)
		}

		for i := 1; i < len(parts); i++ {
			g.dep(parts[i], parts[i-1])
		}
		if len(parts) > 0 {
			g.dep(parts[0], s)
			g.dep(e, parts[len(parts)-1])
		} else {
			g.dep(e, s)
		}
	}

	for _, r := range refs {
		var from int
		if r.flowLevel {
			from = startNode[r.fi]
		} else {
			from = msgNodeByPos[[2]int{r.fi, r.msgIdx}]
		}
		var to int
		if r.refMsg == "" {
			to = endNode[flowIndexByName(flows, r.refFlow)]
		} else {
			to = msgNodeByName[r.refFlow][r.refMsg]
		}
		g.dep(from, to)
	}
	return g
}

// dep 记录 from 依赖 to(from 在 to 之后发生)。
func (g *StartAfterGraph) dep(from, to int) {
	g.Adj[from] = append(g.Adj[from], to)
}

// DetectCycle 用三色 DFS 找环;有环则返回"循环依赖"错误,环上节点 label 用 " → " 连接。
// 按节点序遍历,报错路径稳定(不依赖 map 迭代序)。无环返回 nil。
func (g *StartAfterGraph) DetectCycle() error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make([]int, len(g.Nodes))
	var stack []int
	var dfs func(u int) error
	dfs = func(u int) error {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range g.Adj[u] {
			switch color[v] {
			case gray:
				cycle := make([]string, 0, len(stack)-indexOfInt(stack, v)+1)
				for _, n := range stack[indexOfInt(stack, v):] {
					cycle = append(cycle, g.Nodes[n].Label)
				}
				cycle = append(cycle, g.Nodes[v].Label)
				return fmt.Errorf("start_after 循环依赖: %s", strings.Join(cycle, " → "))
			case white:
				if err := dfs(v); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
		return nil
	}
	for i := range g.Nodes {
		if color[i] == white {
			if err := dfs(i); err != nil {
				return err
			}
		}
	}
	return nil
}

// TopoOrder 返回事件节点的拓扑序(依赖在前,被依赖... 见下)。边语义为"X 依赖 Y(X 在 Y 之后)",
// 故 Y(被依赖项)应先算出时刻;拓扑序把被依赖项排在前面。返回的序里,每个节点出现在它所有
// 依赖项之后。按节点序做稳定 Kahn,保证确定性(不依赖 map 迭代序)。图有环时返回 nil。
func (g *StartAfterGraph) TopoOrder() []int {
	n := len(g.Nodes)
	// indeg[i] = 有多少条边指向 i(即有多少节点依赖 i)。
	// 边 from->to 表示 from 依赖 to;故 to 的入度 = 依赖 to 的节点数。拓扑序要 to 先出。
	indeg := make([]int, n)
	for _, adj := range g.Adj {
		for _, to := range adj {
			indeg[to]++
		}
	}
	// 用按序号升序的最小堆语义:每次取序号最小的入度为 0 节点,保证稳定。
	var queue []int
	for i := 0; i < n; i++ {
		if indeg[i] == 0 {
			queue = append(queue, i)
		}
	}
	// queue 保持升序插入;取出首元素即可(最小序号优先)。
	out := make([]int, 0, n)
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		out = append(out, u)
		for _, to := range g.Adj[u] {
			indeg[to]--
			if indeg[to] == 0 {
				// 插入并保持升序,保证稳定确定性。
				pos := sortSearchInt(queue, to)
				queue = append(queue, 0)
				copy(queue[pos+1:], queue[pos:])
				queue[pos] = to
			}
		}
	}
	if len(out) != n {
		return nil // 有环
	}
	return out
}

// sortSearchInt 返回 v 在已升序的 slice 中应插入的位置(首个 > v 的下标)。
func sortSearchInt(slice []int, v int) int {
	lo, hi := 0, len(slice)
	for lo < hi {
		mid := (lo + hi) / 2
		if slice[mid] < v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}
