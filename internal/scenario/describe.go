package scenario

import (
	"fmt"
	"strings"
	"time"
)

// PacketSummary 是用于展示生成结果的单包摘要。
//
// Left/Right 是归一化方向后的左右端点展示串:有 TCP/UDP 端口时为 "ip:port",无端口时为 "ip",
// 无 IP 时为 "-"。Arrow 为 "->"(base 方向)或 "<-"(反向)。方向以第一个含 IP 的包为基准,
// 反向包的端点也归一到 base 方向(左=base 源端、右=base 目的端),仅箭头翻转。
type PacketSummary struct {
	Left  string
	Arrow string
	Right string
	Stack string
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

// summarizePacketWithBase 计算单包摘要的方向与端点;hasBase 时把双向会话归一到 base 方向。
// 端点串含端口(TCP/UDP):正向用 src 端口在左、dst 端口在右;反向交换,使左恒为 base 源端。
func summarizePacketWithBase(p Packet, baseSrc, baseDst string, hasBase bool) PacketSummary {
	src, dst, sport, dport, hasIP, hasPort := packetIPPortPair(p)
	left, right, arrow := "-", "-", "->"
	if hasIP {
		switch {
		case hasBase && src == baseSrc && dst == baseDst:
			// 正向:src(=baseSrc)端点在左,dst(=baseDst)端点在右,端口不换。
			left = endpoint(baseSrc, sport, hasPort)
			right = endpoint(baseDst, dport, hasPort)
			arrow = "->"
		case hasBase && src == baseDst && dst == baseSrc:
			// 反向:实际 src=baseDst、dst=baseSrc;归一后左=baseSrc(取实际 dst 端口=dport)、右=baseDst(取实际 src 端口=sport)。
			left = endpoint(baseSrc, dport, hasPort)
			right = endpoint(baseDst, sport, hasPort)
			arrow = "<-"
		default:
			left = endpoint(src, sport, hasPort)
			right = endpoint(dst, dport, hasPort)
			arrow = "->"
		}
	}
	return PacketSummary{
		Left:  left,
		Arrow: arrow,
		Right: right,
		Stack: displayStack(p),
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

func firstIPPair(pkts []Packet) (string, string, bool) {
	for _, p := range pkts {
		if src, dst, ok := packetIPPair(p); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

// packetIPPair 返回包里最近一层 IP(IPv4 或 IPv6)的 src/dst 文本,供方向归一化基准使用。
func packetIPPair(p Packet) (string, string, bool) {
	src, dst, _, _, ok, _ := packetIPPortPair(p)
	return src, dst, ok
}

// packetIPPortPair 返回包里最近一层(innermost)IP 的 src/dst,以及最近一层 TCP/UDP 的
// sport/dport。取最内层与摘要展示口径一致(隧道场景显示内层 IP+传输层端口);hasPort 为
// false 表示无 TCP/UDP 层(如 ICMP、纯 eth、payload_hex),此时不展示端口。
func packetIPPortPair(p Packet) (srcIP, dstIP string, srcPort, dstPort uint16, hasIP, hasPort bool) {
	for _, l := range p.Stack {
		switch f := l.Fields.(type) {
		case *IPv4Fields:
			srcIP, dstIP, hasIP = f.Src, f.Dst, true
		case *IPv6Fields:
			srcIP, dstIP, hasIP = f.Src, f.Dst, true
		case *TCPFields:
			srcPort, dstPort, hasPort = f.SPort, f.DPort, true
		case *UDPFields:
			srcPort, dstPort, hasPort = f.SPort, f.DPort, true
		}
	}
	return
}

// endpoint 拼出摘要端点展示串:有端口且非 0 时 "ip:port",否则 "ip";无 IP 时 "-"。
// IPv6 地址含冒号,直拼 "ip:port" 会与地址本身的冒号混淆(且 "2001:db8::1:443" 本身是合法
// IPv6 地址),故 IPv6 按 RFC 3986 加方括号写作 "[ip]:port";IPv4 无冒号,直接 "ip:port"。
func endpoint(ip string, port uint16, hasPort bool) string {
	if ip == "" {
		return "-"
	}
	if !hasPort || port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
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
	case "ftp_request", "ftp_response":
		return "ftp", true
	case "smtp_request", "smtp_response":
		return "smtp", true
	case "pop3_request", "pop3_response":
		return "pop3", true
	case "eml_data":
		return "eml", true // 协议无关的 RFC 5322 邮件内容
	case "payload", "payload_hex", "tcp_session":
		return "", false
	default:
		return layerType, true
	}
}
