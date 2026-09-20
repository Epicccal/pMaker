package scenario

import (
	"fmt"
	"strings"
)

// mtu 自动分片的校验规则(硬错部分)。
//
// 校验面:
//   - 同一 stack 内两层 IP 同时写 mtu → 硬错(写在哪层分哪层,两层同写语义歧义);
//   - mtu 与逐字段覆盖互斥(total_length/header_length/checksum / payload_length):
//     自动分片的前提是逐片自动重算长度与 checksum,任何"原样落值"的覆盖都会让
//     各片携带同一声明值,语义必错;
//   - mtu 小于结构下限(IPv4:头长 + 8;IPv6:40 + 8 + 8),切不出至少 8 字节的片;
//   - quote.stack 内写 mtu → 硬错(quote 是载荷提取视图,不是上线的包);
//   - quote_from 引用环(含自引)→ 硬错:快照机制要求被引包先于引用包完成序列化,
//     环无论声明顺序如何都无法满足,校验阶段统一拦截。
//
// mtu < 68 / 1280 的 RFC 下限走软告警(CheckMTUBelowMinimum),不在此处。

// mtuStructMinimum 返回一层数据报的最小结构下限:MTU 至少要容纳 IP 头 + 一片 8 字节
// 对齐的载荷。IPv4 = 20(头)+ 8;IPv6 = 40(主头)+ 8(Fragment 扩展头)+ 8(片偏移单位)。
func mtuStructuralMinimum(family string) int {
	if family == "ipv6" {
		return 40 + 8 + 8
	}
	return 20 + 8
}

// validateMTUIn 校验一个 stack 里 IP 层的 mtu 声明(standalone packet 的顶层 stack
// 与 flow.stack 共用:message.stack 不允许 IP 层,quote.stack 的 mtu 由
// checkQuoteStackMTU 另行拦截)。
//
// MTU 是 int(零值=未写)而非 *int:与分片互斥的字段(total_length 等)都是指针,
// "写 0 的 mtu" 等价于未写(0 永不分片,且 < 结构下限会被拦),无歧义窗口。
func validateMTUIn(stack []Layer) error {
	seen := ""
	for i, l := range stack {
		var mtu int
		switch f := l.Fields.(type) {
		case *IPv4Fields:
			mtu = f.MTU
		case *IPv6Fields:
			mtu = f.MTU
		default:
			continue
		}
		if mtu == 0 {
			continue
		}
		if seen != "" {
			return fmt.Errorf("stack[%d].%s: 同一 stack 内两层 IP 同时写 mtu(已有 ipv4/ipv6 写了 mtu);mtu 只能写在其中一层", i, l.Type)
		}
		seen = l.Type
	}
	return nil
}

// validateMTUFields 校验单个 IP 层的 mtu 声明(硬错部分,与覆盖字段互斥、结构下限)。
//
// conflicts 是该层与 mtu 互斥、且实际已写的覆盖字段名(ipv4:total_length/header_length/
// checksum;ipv6:payload_length),调用方按固定顺序拼好传入,保证报错文案确定。
// mtu 与覆盖互斥的原因:自动分片的前提是逐片自动重算长度与 checksum,任何
// "原样落值"的覆盖都会让各片携带同一声明值,语义必错。
func validateMTUFields(family string, mtu int, conflicts []string) error {
	if mtu == 0 {
		return nil
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("mtu 与 %s 互斥:自动分片逐片重算长度与 checksum,覆盖值会被各片原样携带;要构造特定长度/checksum 的包请去掉 mtu", strings.Join(conflicts, "/"))
	}
	if mtu < mtuStructuralMinimum(family) {
		return fmt.Errorf("mtu=%d 小于结构下限 %d(%s:至少容纳 IP 头 + 一片 8 字节对齐载荷),切不出合法分片", mtu, mtuStructuralMinimum(family), family)
	}
	return nil
}

// RFC 规定的每包最小 MTU:低于它不硬错(测试场景可能就要小 MTU),只打软告警。
const (
	rfcMinMTUv4 = 68   // RFC 791:所有主机须能收 ≤68 字节的数据报
	rfcMinMTUv6 = 1280 // RFC 8200:链路 MTU 下限
)

// CheckMTUBelowMinimum 扫描 packets 与 flows 的 IP 层,mtu 低于 RFC 下限时打软告警
// (ipv4 < 68,ipv6 < 1280)。低于下限照常出包:分片器只要求 mtu ≥ 结构下限,
// 更小的 mtu 是合法的极端测试场景(如验证重组端的超小片处理)。
func CheckMTUBelowMinimum(s *Scenario) []Diagnostic {
	if s == nil {
		return nil
	}
	var ws []Diagnostic
	check := func(path, family string, mtu int, label string) {
		if mtu == 0 {
			return
		}
		limit := rfcMinMTUv4
		code := CodeIPv4MTUBelowMinimum
		if family == "ipv6" {
			limit = rfcMinMTUv6
			code = CodeIPv6MTUBelowMinimum
		}
		if mtu >= limit {
			return
		}
		ws = append(ws, warnf(code, fmt.Sprintf("%s.mtu", path),
			"%s: mtu=%d 低于 RFC 最小 MTU %d(%s);照常分片,仅提示真实链路通常不出现此值",
			label, mtu, limit, family))
	}
	for i, p := range s.Packets {
		for j, l := range p.Stack {
			switch f := l.Fields.(type) {
			case *IPv4Fields:
				check(packetStackPath(i, j), "ipv4", f.MTU, fmt.Sprintf("packets[%d].stack[%d].ipv4", i, j))
			case *IPv6Fields:
				check(packetStackPath(i, j), "ipv6", f.MTU, fmt.Sprintf("packets[%d].stack[%d].ipv6", i, j))
			}
		}
	}
	for i, f := range s.Flows {
		for j, l := range f.Stack {
			switch g := l.Fields.(type) {
			case *IPv4Fields:
				check(flowStackPath(i, j), "ipv4", g.MTU, fmt.Sprintf("flows[%d](%s).stack[%d].ipv4", i, flowLabel(f.Name, i), j))
			case *IPv6Fields:
				check(flowStackPath(i, j), "ipv6", g.MTU, fmt.Sprintf("flows[%d](%s).stack[%d].ipv6", i, flowLabel(f.Name, i), j))
			}
		}
	}
	return ws
}

// checkQuoteStackMTU 检查 quote.stack 内是否写了 mtu(硬错)。quote 是载荷提取视图,
// 不是上线的包,对它分片无语义;要引用真实分片,把被引包写成独立 packet 走 quote_from。
func checkQuoteStackMTU(l Layer) error {
	var mtu int
	switch f := l.Fields.(type) {
	case *IPv4Fields:
		mtu = f.MTU
	case *IPv6Fields:
		mtu = f.MTU
	default:
		return nil
	}
	if mtu != 0 {
		return fmt.Errorf("quote.stack 内的 %s 不支持 mtu(quote 是载荷提取视图,不是上线的包,分片无语义);要引用真实分片结果,把被引包写成独立 packet 走 quote_from", l.Type)
	}
	return nil
}

// quoteFromNames 收集一个层产生的全部 quote_from 引用名:顶层 quote_from 一条,
// quote.stack 内嵌的 ICMP/ICMPv6 层递归再收集(嵌套可任意深)。其他层类型无引用,
// 返回空。构建期 icmpPayload 对 quote.stack 递归序列化,嵌套的 quote_from 是
// 真实依赖边,校验(存在/唯一/环)必须与之同口径。
func quoteFromNames(l Layer) []string {
	var top string
	var quote *Packet
	switch f := l.Fields.(type) {
	case *ICMPFields:
		top, quote = f.QuoteFrom, f.Quote
	case *ICMPv6Fields:
		top, quote = f.QuoteFrom, f.Quote
	default:
		return nil
	}
	var names []string
	if top != "" {
		names = append(names, top)
	}
	if quote != nil {
		for _, inner := range quote.Stack {
			names = append(names, quoteFromNames(inner)...)
		}
	}
	return names
}

// CheckQuoteFromCycle 对命名 packet 的 quote_from 依赖边做 DFS,引用环(含自引)报硬错。
// quote_from 的快照机制要求被引包先于引用包完成序列化,环无论声明顺序如何都无法
// 满足该契约,故在校验阶段统一拦截。
//
// 边的方向:引用包 → 被引包(引用依赖被引)。环即 A 引 B、B 引 A(或自引)。
func CheckQuoteFromCycle(s *Scenario) error {
	if s == nil {
		return nil
	}
	// 名字 → packet 下标(quote_from 引用要求唯一,重名已由 validateQuoteFrom 拦截;
	// 这里取首个匹配即可,重复名到不了这一步)。
	idx := map[string]int{}
	for i, p := range s.Packets {
		if p.Name != "" {
			if _, dup := idx[p.Name]; !dup {
				idx[p.Name] = i
			}
		}
	}
	// 邻接表:i 引用的被引 packet 下标集合。除顶层 stack 外还扫 quote.stack 内嵌的
	// ICMP/ICMPv6 层(quoteFromNames 递归),构建期会递归序列化 quote,嵌套引用
	// 同样是依赖边。
	adj := make([][]int, len(s.Packets))
	for i, p := range s.Packets {
		for _, l := range p.Stack {
			for _, name := range quoteFromNames(l) {
				if j, ok := idx[name]; ok {
					adj[i] = append(adj[i], j)
				}
			}
		}
	}
	// 三色 DFS:0=未访,1=在栈(灰),2=完成。回边指向灰节点即环。
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make([]int, len(s.Packets))
	var visit func(i int, path []string) error
	visit = func(i int, path []string) error {
		color[i] = gray
		path = append(path, s.Packets[i].Name)
		for _, next := range adj[i] {
			switch color[next] {
			case gray:
				// 环路径:从 path 中被引包首次出现处截到当前,再闭合回被引包。
				start := 0
				for k, n := range path {
					if n == s.Packets[next].Name {
						start = k
						break
					}
				}
				cycle := append(append([]string{}, path[start:]...), s.Packets[next].Name)
				return fmt.Errorf("quote_from 引用环: %s", strings.Join(cycle, " → "))
			case white:
				if err := visit(next, path); err != nil {
					return err
				}
			}
		}
		color[i] = black
		return nil
	}
	for i := range s.Packets {
		if color[i] == white {
			if err := visit(i, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
