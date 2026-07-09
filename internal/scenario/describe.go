package scenario

import (
	"fmt"
	"strings"
)

// PacketSummary 是用于展示生成结果的单包摘要。
type PacketSummary struct {
	LeftIP  string
	Arrow   string
	RightIP string
	Stack   string
}

// SummarizePackets 从已展开的包列表生成展示用摘要。
func SummarizePackets(pkts []Packet) []PacketSummary {
	baseSrc, baseDst, hasBase := firstIPv4Pair(pkts)

	out := make([]PacketSummary, 0, len(pkts))
	for _, p := range pkts {
		src, dst, ok := packetIPv4Pair(p)
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
		out = append(out, PacketSummary{
			LeftIP:  left,
			Arrow:   arrow,
			RightIP: right,
			Stack:   displayStack(p),
		})
	}
	return out
}

// FormatPacketSummary 按 CLI 输出格式格式化单包摘要,index 从 1 开始传入。
func FormatPacketSummary(index int, s PacketSummary) string {
	return fmt.Sprintf("[%d] %s %s %s  %s", index, s.LeftIP, s.Arrow, s.RightIP, s.Stack)
}

func firstIPv4Pair(pkts []Packet) (string, string, bool) {
	for _, p := range pkts {
		if src, dst, ok := packetIPv4Pair(p); ok {
			return src, dst, true
		}
	}
	return "", "", false
}

func packetIPv4Pair(p Packet) (string, string, bool) {
	var src, dst string
	ok := false
	for _, l := range p.Stack {
		if f, isIPv4 := l.Fields.(*IPv4Fields); isIPv4 {
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
