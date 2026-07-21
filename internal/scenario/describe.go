package scenario

import (
	"fmt"
	"strings"
	"time"
)

// PacketSummary 是用于展示生成结果的单包摘要。
type PacketSummary struct {
	LeftIP  string
	Arrow   string
	RightIP string
	Stack   string
	// Time 是该包的显式时间戳(来自 PlannedPacket.Time);HasTime 为 false 时表示
	// 摘要来源无时间信息(SummarizePackets 路径),FormatPacketSummary 不输出时间列。
	Time    time.Time
	HasTime bool
}

// SummarizePackets 从已展开的包列表生成展示用摘要(不含时间信息)。
func SummarizePackets(pkts []Packet) []PacketSummary {
	baseSrc, baseDst, hasBase := firstIPPair(pkts)

	out := make([]PacketSummary, 0, len(pkts))
	for _, p := range pkts {
		out = append(out, summarizePacketWithBase(p, baseSrc, baseDst, hasBase))
	}
	return out
}

// summarizePacketWithBase 计算单包摘要的方向与层栈;hasBase 时把双向会话归一到 base 方向。
func summarizePacketWithBase(p Packet, baseSrc, baseDst string, hasBase bool) PacketSummary {
	src, dst, ok := packetIPPair(p)
	left, right, arrow := "-", "-", "->"
	if ok {
		switch {
		case hasBase && src == baseSrc && dst == baseDst:
			left, right, arrow = baseSrc, baseDst, "->"
		case hasBase && src == baseDst && dst == baseSrc:
			left, right, arrow = baseSrc, baseDst, "<-"
		default:
			left, right, arrow = src, dst, "->"
		}
	}
	return PacketSummary{
		LeftIP:  left,
		Arrow:   arrow,
		RightIP: right,
		Stack:   displayStack(p),
	}
}

// SummarizePlanned 从已汇流排序的 PlannedPacket 列表生成展示用摘要。
// 与 SummarizePackets 不同,此路径保留了 PlannedPacket.Time,FormatPacketSummary 会输出时间列。
// 方向归一化与 SummarizePackets 一致:以第一个含 IP 的包为基准,反向包显示为 <-。
func SummarizePlanned(planned []PlannedPacket) []PacketSummary {
	baseSrc, baseDst, hasBase := firstPlannedIPPair(planned)

	out := make([]PacketSummary, 0, len(planned))
	for _, pp := range planned {
		s := summarizePacketWithBase(pp.Packet, baseSrc, baseDst, hasBase)
		s.Time = pp.Time
		s.HasTime = true
		out = append(out, s)
	}
	return out
}

// firstPlannedIPPair 返回 planned 列表中第一个含 IP 层的包的 src/dst,作为方向归一化基准。
func firstPlannedIPPair(planned []PlannedPacket) (string, string, bool) {
	for _, pp := range planned {
		if src, dst, ok := packetIPPair(pp.Packet); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

// FormatPacketSummary 按 CLI 输出格式格式化单包摘要,index 从 1 开始传入。
// 单行格式:列宽取本行自身,不做跨行补齐——适合单包输出或向后兼容,输出与历史逐字节等价。
// 多行对齐(序号位数、左右 IP 宽度跨行补齐)请用 FormatPacketSummaries。
//
// 当摘要带时间信息(HasTime,来自 PlannedPacket)时,在序号与源 IP 之间插入时间列
// (ISO8601 带微秒,与 base_time 语义一致);否则保持不含时间的原格式。
func FormatPacketSummary(index int, s PacketSummary) string {
	return formatRow(index, s, indexWidth(index), len(s.LeftIP), len(s.RightIP))
}

// FormatPacketSummaries 批量格式化摘要并跨行对齐:index 从 1 开始;序号按最大位数、
// 左右 IP 按各自最大宽度补齐,使每行的 ']'(序号尾)、箭头、协议栈起点落同一列。
//
// 对齐是整表属性——单行无从知晓其它行的宽度,故多行输出必须走此函数而非逐行 FormatPacketSummary。
// 时间列恒为定宽(ISO8601 带微秒,AbsTime 结构性保证 UTC,故每行 27 字符),无需补齐。
func FormatPacketSummaries(summaries []PacketSummary) []string {
	idxW := indexWidth(len(summaries))
	leftW, rightW := 0, 0
	for _, s := range summaries {
		leftW = max(leftW, len(s.LeftIP))
		rightW = max(rightW, len(s.RightIP))
	}
	out := make([]string, len(summaries))
	for i, s := range summaries {
		out[i] = formatRow(i+1, s, idxW, leftW, rightW)
	}
	return out
}

// formatRow 按给定列宽格式化单行;列宽由调用方计算(单行=自宽、无补齐;多行=跨行最大宽)。
// 序号在括号内右对齐(数字列惯例);左右 IP 左对齐补齐(便于纵向扫读源/目地址),
// 箭头与协议栈列因此跨行对齐。两空格分隔 rightIP 与 stack,与历史格式一致。
func formatRow(index int, s PacketSummary, idxW, leftW, rightW int) string {
	if !s.HasTime {
		return fmt.Sprintf("[%*d] %-*s %s %-*s  %s",
			idxW, index, leftW, s.LeftIP, s.Arrow, rightW, s.RightIP, s.Stack)
	}
	return fmt.Sprintf("[%*d] %s %-*s %s %-*s  %s",
		idxW, index, s.Time.Format(packetSummaryTimeLayout),
		leftW, s.LeftIP, s.Arrow, rightW, s.RightIP, s.Stack)
}

// indexWidth 返回 1..n 这些序号所需的最少位数(n 为包数):1..9→1,10..99→2,…。n<=0→1。
// 与最大序号(=n)位数一致,故用作序号列宽。
func indexWidth(n int) int {
	if n <= 0 {
		return 1
	}
	w := 1
	for n >= 10 {
		n /= 10
		w++
	}
	return w
}

// packetSummaryTimeLayout 是摘要时间列的展示格式:ISO8601 带微秒。
// 与 base_time 的 ISO8601 语义保持一致,微秒精度覆盖 pcap 典型时间戳精度。
const packetSummaryTimeLayout = "2006-01-02T15:04:05.000000Z07:00"

func firstIPPair(pkts []Packet) (string, string, bool) {
	for _, p := range pkts {
		if src, dst, ok := packetIPPair(p); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

// packetIPPair 返回包里最近一层 IP(IPv4 或 IPv6)的 src/dst 文本,供摘要展示。
func packetIPPair(p Packet) (string, string, bool) {
	var src, dst string
	ok := false
	for _, l := range p.Stack {
		switch f := l.Fields.(type) {
		case *IPv4Fields:
			src, dst, ok = f.Src, f.Dst, true
		case *IPv6Fields:
			src, dst, ok = f.Src, f.Dst, true
		}
	}
	return src, dst, ok
}

func displayStack(p Packet) string {
	parts := SummaryLayerNames(p.Stack)
	parts = append(parts, p.SummaryLayers...)
	return strings.Join(parts, "/")
}

// SummaryLayerNames 返回 stack 中适合在人类摘要里展示的协议层名。
func SummaryLayerNames(stack []Layer) []string {
	parts := make([]string, 0, len(stack))
	for _, l := range stack {
		name, ok := summaryLayerName(l.Type)
		if ok {
			parts = append(parts, name)
		}
	}
	return parts
}

func summaryLayerName(layerType string) (string, bool) {
	switch layerType {
	case "http_request", "http_response":
		return "http", true
	case "payload", "payload_hex", "tcp_session":
		return "", false
	default:
		return layerType, true
	}
}
