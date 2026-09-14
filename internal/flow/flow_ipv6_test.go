package flow_test

import (
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// TestFlowIPv6Stack 验证 flow 对 IPv6 网络层的支持:
// parseFlowStack 能正确解析 IPv6Fields,emit 产出 ipv6 层且 HopLimit 正确。
func TestFlowIPv6Stack(t *testing.T) {
	mss := uint16(1460)
	f := scenario.FlowSpec{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{
				Src:      "2001:db8::1",
				Dst:      "2001:db8::2",
				HopLimit: ptrUint8(128),
			}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000, MSS: &mss}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
		},
		Messages: []scenario.Message{{
			From: "src",
			Stack: []scenario.Layer{{
				Type:   "payload_hex",
				Fields: scenario.PayloadHex("0xabcd"),
			}},
		}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// 验证每个展开包的网络层类型为 ipv6,不含 ipv4;地址必须是 {2001:db8::1, 2001:db8::2} 之一对。
	for _, p := range pkts {
		var foundIPv6, foundIPv4 bool
		for _, l := range p.Packet.Stack {
			switch l.Type {
			case "ipv6":
				foundIPv6 = true
				ip, ok := l.Fields.(*scenario.IPv6Fields)
				if !ok {
					t.Errorf("ipv6 层 Fields 类型错误: %T", l.Fields)
					continue
				}
				pair := ip.Src + "->" + ip.Dst
				want := map[string]bool{
					"2001:db8::1->2001:db8::2": true, // src 方向
					"2001:db8::2->2001:db8::1": true, // dst 方向(反转)
				}
				if !want[pair] {
					t.Errorf("ipv6 Src=%q Dst=%q,期望 2001:db8::1↔2001:db8::2 的某一方向", ip.Src, ip.Dst)
				}
				if ip.HopLimit == nil || *ip.HopLimit != 128 {
					t.Errorf("ipv6 HopLimit=%v,期望 128", ip.HopLimit)
				}
			case "ipv4":
				foundIPv4 = true
			}
		}
		if !foundIPv6 {
			t.Error("流内某包缺少 ipv6 网络层")
		}
		if foundIPv4 {
			t.Error("IPv6 flow 不应产出 ipv4 网络层")
		}
	}
	// 握手应产生一个 SYN(sport=1111、dport=80 的纯 SYN),且 SYN 携带 MSS option=1460。
	var syn *scenario.TCPFields
	for _, p := range pkts {
		tc := tcpOf(p.Packet)
		if tc == nil || !contains(tc.Flags, "SYN") || contains(tc.Flags, "ACK") {
			continue
		}
		if syn != nil {
			t.Fatalf("期望 1 个 SYN,找到多个")
		}
		syn = tc
	}
	if syn == nil {
		t.Fatal("未找到 SYN 包")
	}
	if syn.SPort != 1111 || syn.DPort != 80 {
		t.Errorf("SYN sport/dport=%d/%d,期望 1111/80", syn.SPort, syn.DPort)
	}
	if syn.MSS == nil || *syn.MSS != 1460 {
		t.Errorf("SYN 应携带 MSS=1460(通告值),得到 %v", syn.MSS)
	}
}

// TestFlowIPv6ReverseDirection 验证 IPv6 flow 的 src/dst 反转:
// from=dst 的消息其 stack 的 eth/ipv6/tcp 方向正确反转(不含源 IP 的 16 字节 IPv6 地址)。
func TestFlowIPv6ReverseDirection(t *testing.T) {
	f := scenario.FlowSpec{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
		},
		Messages: []scenario.Message{
			{From: "src", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "req"}}}},
			{From: "dst", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "rep"}}}},
		},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// 收集数据段数据:src 方向的数据段其 ipv6 Src 应为 2001:db8::1;
	// dst 方向的数据段其 ipv6 Src 应为 2001:db8::2。
	var srcIPs, dstIPs []string
	for _, p := range pkts {
		var ip *scenario.IPv6Fields
		for _, l := range p.Packet.Stack {
			if l.Type == "ipv6" {
				ip = l.Fields.(*scenario.IPv6Fields)
			}
		}
		if ip == nil {
			continue
		}
		tc := tcpOf(p.Packet)
		if tc == nil || !contains(tc.Flags, "PSH") {
			continue
		}
		if tc.SPort == 1111 {
			srcIPs = append(srcIPs, ip.Src)
		} else {
			dstIPs = append(dstIPs, ip.Src)
		}
	}
	if len(srcIPs) != 1 || srcIPs[0] != "2001:db8::1" {
		t.Errorf("src 方向 PSH 的 ipv6 Src=%v,期望 [2001:db8::1]", srcIPs)
	}
	if len(dstIPs) != 1 || dstIPs[0] != "2001:db8::2" {
		t.Errorf("dst 方向 PSH 的 ipv6 Src=%v,期望 [2001:db8::2]", dstIPs)
	}
}

func ptrUint8(v uint8) *uint8 {
	return &v
}
