package summary

import (
	"fmt"
	"strings"
	"time"

	"github.com/Epicccal/pMaker/internal/scenario"
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
func SummarizePackets(pkts []scenario.Packet) []PacketSummary {
	baseSrc, baseDst, hasBase := firstIPPair(pkts)

	out := make([]PacketSummary, 0, len(pkts))
	for _, p := range pkts {
		out = append(out, summarizePacketWithBase(p, baseSrc, baseDst, hasBase))
	}
	return out
}

// summarizePacketWithBase 计算单包摘要的方向与端点;hasBase 时把双向会话归一到 base 方向。
// 端点串含端口(TCP/UDP):正向用 src 端口在左、dst 端口在右;反向交换,使左恒为 base 源端。
func summarizePacketWithBase(p scenario.Packet, baseSrc, baseDst string, hasBase bool) PacketSummary {
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
func SummarizePlanned(planned []scenario.PlannedPacket) []PacketSummary {
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
func firstPlannedIPPair(planned []scenario.PlannedPacket) (string, string, bool) {
	for _, pp := range planned {
		if src, dst, ok := packetIPPair(pp.Packet); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

func firstIPPair(pkts []scenario.Packet) (string, string, bool) {
	for _, p := range pkts {
		if src, dst, ok := packetIPPair(p); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

// packetIPPair 返回包里最近一层 IP(IPv4 或 IPv6)的 src/dst 文本,供方向归一化基准使用。
func packetIPPair(p scenario.Packet) (string, string, bool) {
	src, dst, _, _, ok, _ := packetIPPortPair(p)
	return src, dst, ok
}

// packetIPPortPair 返回包里最近一层(innermost)IP 的 src/dst,以及最近一层 TCP/UDP 的
// sport/dport。取最内层与摘要展示口径一致(隧道场景显示内层 IP+传输层端口);hasPort 为
// false 表示无 TCP/UDP 层(如 ICMP、纯 eth、payload_hex),此时不展示端口。
func packetIPPortPair(p scenario.Packet) (srcIP, dstIP string, srcPort, dstPort uint16, hasIP, hasPort bool) {
	for _, l := range p.Stack {
		switch f := l.Fields.(type) {
		case *scenario.IPv4Fields:
			srcIP, dstIP, hasIP = f.Src, f.Dst, true
		case *scenario.IPv6Fields:
			srcIP, dstIP, hasIP = f.Src, f.Dst, true
		case *scenario.TCPFields:
			srcPort, dstPort, hasPort = f.SPort, f.DPort, true
		case *scenario.UDPFields:
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

// displayStack 拼接摘要的协议栈展示串:层名白名单取自 scenario.SummaryLayerNames
// (schema 元信息,留在 scenario),再接 flow 填的 SummaryLayers。
func displayStack(p scenario.Packet) string {
	parts := scenario.SummaryLayerNames(p.Stack)
	parts = append(parts, p.SummaryLayers...)
	return strings.Join(parts, "/")
}
