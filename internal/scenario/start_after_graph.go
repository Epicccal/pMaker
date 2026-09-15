package scenario

import (
	"fmt"
	"strings"
)

// StartAfterNode 是事件粒度依赖图的一个节点。节点代表一个"事件":
// flow 的起点 / 终点,或一条参与 start_after 的 message。ID 为该节点在图中的稳定序号,
// 仅供内部索引;对外含义由 Label 表达。
type StartAfterNode struct {
	Label string // 可读标签,如 "start:control" / "msg:control.pasv" / "end:data"
}

// StartAfterGraph 是事件粒度的有向依赖图:边 X→Y 表示"X 依赖 Y(X 在 Y 之后发生)"。
// 仅供 validateStartAfter 做三色 DFS 检环;plan 的算时阶段(scheduler)按同一事件粒度
// 规则独立递归,不消费本图。
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
// 该图仅供 validateStartAfter 检环;它**有意省略非参与消息**(它们的时间在 plan 算时阶段按流内链式游标
// 另行推进,不影响依赖结构)。返回的边方向为"X 依赖 Y";检环时回边即环。
func BuildStartAfterGraph(flows []FlowSpec) *StartAfterGraph {
	g := &StartAfterGraph{key: map[string]int{}}
	add := func(label string) int {
		if i, ok := g.key[label]; ok {
			return i
		}
		i := len(g.Nodes)
		g.Nodes = append(g.Nodes, StartAfterNode{Label: label})
		g.Adj = append(g.Adj, nil)
		g.key[label] = i
		return i
	}

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
		s := add("start:" + label)
		e := add("end:" + label)
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
			n := add(mlabel)
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
