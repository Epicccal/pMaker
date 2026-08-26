package summary

import (
	"fmt"
)

// FormatPacketSummary 按 CLI 输出格式格式化单包摘要,index 从 1 开始传入。
// 单行格式:列宽取本行自身,不做跨行补齐——适合单包输出或向后兼容,输出与历史逐字节等价。
// 多行对齐(序号位数、左右端点宽度跨行补齐)请用 FormatPacketSummaries。
//
// 当摘要带时间信息(HasTime,来自 PlannedPacket)时,在序号与左端点之间插入时间列
// (ISO8601 带微秒,与 base_time 语义一致);否则保持不含时间的原格式。
func FormatPacketSummary(index int, s PacketSummary) string {
	return formatRow(index, s, indexWidth(index), len(s.Left), len(s.Right))
}

// FormatPacketSummaries 批量格式化摘要并跨行对齐:index 从 1 开始;序号按最大位数、
// 左右端点按各自最大宽度补齐,使每行的 ']'(序号尾)、箭头、协议栈起点落同一列。
//
// 对齐是整表属性——单行无从知晓其它行的宽度,故多行输出必须走此函数而非逐行 FormatPacketSummary。
// 时间列恒为定宽(ISO8601 带微秒,AbsTime 结构性保证 UTC,故每行 27 字符),无需补齐。
func FormatPacketSummaries(summaries []PacketSummary) []string {
	idxW := indexWidth(len(summaries))
	leftW, rightW := 0, 0
	for _, s := range summaries {
		leftW = max(leftW, len(s.Left))
		rightW = max(rightW, len(s.Right))
	}
	out := make([]string, len(summaries))
	for i, s := range summaries {
		out[i] = formatRow(i+1, s, idxW, leftW, rightW)
	}
	return out
}

// formatRow 按给定列宽格式化单行;列宽由调用方计算(单行=自宽、无补齐;多行=跨行最大宽)。
// 序号在括号内右对齐(数字列惯例);左右端点左对齐补齐(便于纵向扫读源/目地址),
// 箭头与协议栈列因此跨行对齐。两空格分隔 right 端点与 stack,与历史格式一致。
func formatRow(index int, s PacketSummary, idxW, leftW, rightW int) string {
	if !s.HasTime {
		return fmt.Sprintf("[%*d] %-*s %s %-*s  %s",
			idxW, index, leftW, s.Left, s.Arrow, rightW, s.Right, s.Stack)
	}
	return fmt.Sprintf("[%*d] %s %-*s %s %-*s  %s",
		idxW, index, s.Time.Format(packetSummaryTimeLayout),
		leftW, s.Left, s.Arrow, rightW, s.Right, s.Stack)
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
