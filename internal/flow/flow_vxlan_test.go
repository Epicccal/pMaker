package flow_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 flow.stack 整栈模板下的 VXLAN 隧道会话:
//   - 内外层地址方向反转、VNI/UDP 端口两向不变
//   - seq/ack 只按 inner payload 推进
//   - 整栈字段原样保留(checksum/total_length/traffic_class 等写入后逐包等值)
// 端到端 golden 与 gopacket 回读见 internal/golden/vxlan_test.go。

func uint8Ptr(v uint8) *uint8 { return &v }

// vxlanFlowStack 构造带一层 vxlan 的最小 flow 栈(open/close=none,便于逐包定位)。
func vxlanFlowStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.20", TTL: uint8Ptr(64)}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4789}},
		{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 100}},
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:22:33:44:55:66", Dst: "00:33:44:55:66:77"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20", TTL: uint8Ptr(64)}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
	}
}

// expandVXLAN 展开两条消息(src 方向 "hello"/"world"),返回全部展开包。
func expandVXLAN(t *testing.T) []scenario.PlannedPacket {
	t.Helper()
	f := scenario.FlowSpec{Name: "vx", Stack: vxlanFlowStack()}
	payload := func(b string) scenario.Layer {
		return scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte(b)))}
	}
	f.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{payload("hello")}},
		{From: "src", Stack: []scenario.Layer{payload("world")}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return pkts
}

// layerAt 取第 occ(0 起)个 type 层的 Fields;对 scenario.Packet 与 []scenario.Layer
// 都可用(以 Fields 的动态类型断言取回具体字段结构)。
func layerAt(p any, typ string, occ int) any {
	var layers []scenario.Layer
	switch v := p.(type) {
	case scenario.Packet:
		layers = v.Stack
	case []scenario.Layer:
		layers = v
	}
	for _, l := range layers {
		if l.Type == typ {
			if occ == 0 {
				return l.Fields
			}
			occ--
		}
	}
	return nil
}

// TestFlowVXLANDirectionReversal 反向包(dst→src)outer eth/ip 与 inner eth/ip 一并交换
// src/dst;VNI 与 outer UDP 端口两向不变(设计 §4.1:覆写判据是「跟不跟连接状态走」)。
func TestFlowVXLANDirectionReversal(t *testing.T) {
	pkts := expandVXLAN(t)
	if len(pkts) < 4 {
		t.Fatalf("期望至少 4 个包(数据+ACK × 2),得到 %d", len(pkts))
	}
	fwd, rev := pkts[0].Packet, pkts[1].Packet

	fwdOuterEth := layerAt(fwd, "eth", 0).(*scenario.EthFields)
	revOuterEth := layerAt(rev, "eth", 0).(*scenario.EthFields)
	if revOuterEth.Src != fwdOuterEth.Dst || revOuterEth.Dst != fwdOuterEth.Src {
		t.Errorf("反向 outer eth 未交换:%s->%s vs %s->%s",
			fwdOuterEth.Src, fwdOuterEth.Dst, revOuterEth.Src, revOuterEth.Dst)
	}
	// inner eth(occ=1)同样反转(VM 对是对称端点,内外层同规则)。
	fwdInnerEth := layerAt(fwd, "eth", 1).(*scenario.EthFields)
	revInnerEth := layerAt(rev, "eth", 1).(*scenario.EthFields)
	if revInnerEth.Src != fwdInnerEth.Dst || revInnerEth.Dst != fwdInnerEth.Src {
		t.Errorf("反向 inner eth 未交换")
	}
	// outer/inner ipv4 反转。
	fwdOuterIP := layerAt(fwd, "ipv4", 0).(*scenario.IPv4Fields)
	revOuterIP := layerAt(rev, "ipv4", 0).(*scenario.IPv4Fields)
	if revOuterIP.Src != fwdOuterIP.Dst || revOuterIP.Dst != fwdOuterIP.Src {
		t.Errorf("反向 outer ipv4 未交换")
	}
	fwdInnerIP := layerAt(fwd, "ipv4", 1).(*scenario.IPv4Fields)
	revInnerIP := layerAt(rev, "ipv4", 1).(*scenario.IPv4Fields)
	if revInnerIP.Src != fwdInnerIP.Dst || revInnerIP.Dst != fwdInnerIP.Src {
		t.Errorf("反向 inner ipv4 未交换")
	}
	// TTL 原样保留(模板透传)。
	if fwdOuterIP.TTL == nil || *fwdOuterIP.TTL != 64 {
		t.Errorf("outer ttl 未保留: %v", fwdOuterIP.TTL)
	}
	// VXLAN:两向 VNI 相同。
	fwdVX := layerAt(fwd, "vxlan", 0).(*scenario.VXLANFields)
	revVX := layerAt(rev, "vxlan", 0).(*scenario.VXLANFields)
	if fwdVX.VNI != 100 || revVX.VNI != 100 {
		t.Errorf("VNI 两向应均为 100,得到 %d/%d", fwdVX.VNI, revVX.VNI)
	}
	// outer UDP 端口两向不变(dport=4789,sport 保持声明值;§4.1 sport 派生后续再做)。
	fwdUDP := layerAt(fwd, "udp", 0).(*scenario.UDPFields)
	revUDP := layerAt(rev, "udp", 0).(*scenario.UDPFields)
	if fwdUDP.DPort != 4789 || revUDP.DPort != 4789 {
		t.Errorf("outer dport 两向应均为 4789,得到 %d/%d", fwdUDP.DPort, revUDP.DPort)
	}
	if fwdUDP.SPort != 51000 || revUDP.SPort != 51000 {
		t.Errorf("outer sport 两向应均为声明值 51000,得到 %d/%d", fwdUDP.SPort, revUDP.SPort)
	}
}

// TestFlowVXLANSeqInnerPayloadOnly seq 推进只按 inner TCP payload 字节数(消息 payload),
// VXLAN/outer 头不参与;open=none 时首数据段 seq = client_isn。
func TestFlowVXLANSeqInnerPayloadOnly(t *testing.T) {
	pkts := expandVXLAN(t)
	tc := layerAt(pkts[0].Packet, "tcp", 0).(*scenario.TCPFields)
	if tc.Seq == nil || *tc.Seq != 1000 {
		t.Fatalf("首数据段 seq = %v,期望 1000(client_isn)", tc.Seq)
	}
	tc2 := layerAt(pkts[2].Packet, "tcp", 0).(*scenario.TCPFields)
	if tc2.Seq == nil || *tc2.Seq != 1005 {
		t.Errorf("第二数据段 seq = %v,期望 1005(1000+5,仅 inner payload 推进)", tc2.Seq)
	}
}

// TestFlowVXLANTemplatePreserved 整栈字段原样保留:在模板上写 checksum/total_length/
// traffic_class 等覆盖,展开后每包逐层等值(§5.1「写即覆盖、原样落值、每包同值」)。
func TestFlowVXLANTemplatePreserved(t *testing.T) {
	stack := vxlanFlowStack()
	cksum := scenario.Hex(0x1234)
	tlen := scenario.Hex(0x9999)
	layerAt(stack, "udp", 0).(*scenario.UDPFields).Checksum = &cksum
	layerAt(stack, "ipv4", 0).(*scenario.IPv4Fields).Length = &tlen
	f := scenario.FlowSpec{Name: "vx", Stack: stack}
	payload := func(b string) scenario.Layer {
		return scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte(b)))}
	}
	f.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{payload("hello")}},
		{From: "src", Stack: []scenario.Layer{payload("world!")}}, // 长度不同 → 每包同值更可辨
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for i, pp := range pkts {
		udp := layerAt(pp.Packet, "udp", 0).(*scenario.UDPFields)
		if udp.Checksum == nil || *udp.Checksum != 0x1234 {
			t.Fatalf("包%d outer udp checksum 未保留: %v", i, udp.Checksum)
		}
		ip := layerAt(pp.Packet, "ipv4", 0).(*scenario.IPv4Fields)
		if ip.Length == nil || *ip.Length != 0x9999 {
			t.Fatalf("包%d outer ipv4 total_length 未保留: %v", i, ip.Length)
		}
	}
}

// ---------- VXLAN inner UDP 会话(双 UDP 栈)----------

// vxlanUDPFlowStack 把 inner 段换成 UDP 会话:栈里有两个 udp(outer 隧道 + inner 会话),
// transportIdx 必须定位到 inner(会话层前一层),不能取首个 udp。
func vxlanUDPFlowStack() []scenario.Layer {
	inner := vxlanFlowStack()
	return []scenario.Layer{
		inner[0], // outer eth
		inner[1], // outer ipv4
		inner[2], // outer udp(隧道)
		inner[3], // vxlan
		inner[4], // inner eth
		inner[5], // inner ipv4
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}},
		{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
	}
}

// expandVXLANUDP 展开 inner UDP 会话两条消息("q"/"a" 互为应答),返回全部展开包。
func expandVXLANUDP(t *testing.T) []scenario.PlannedPacket {
	t.Helper()
	f := scenario.FlowSpec{Name: "vxu", Stack: vxlanUDPFlowStack()}
	f.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{vxlanPayload("q")}},
		{From: "dst", Stack: []scenario.Layer{vxlanPayload("a")}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return pkts
}

func vxlanPayload(b string) scenario.Layer {
	return scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte(b)))}
}

// TestFlowVXLANInnerUDPTransportIdx 双 UDP 栈的反向包:inner(会话)UDP 端口被交换,
// outer(隧道)UDP 端口与 VNI 两向不变。transportIdx 若取栈中首个 udp(outer),
// 本测试会以 outer 端口交换 / inner 不动而失败 —— 这正是定位规则的要害。
func TestFlowVXLANInnerUDPTransportIdx(t *testing.T) {
	pkts := expandVXLANUDP(t)
	if len(pkts) != 2 {
		t.Fatalf("UDP 会话两条消息应恰 2 包,得到 %d", len(pkts))
	}
	fwd, rev := pkts[0].Packet, pkts[1].Packet

	fwdOuter := layerAt(fwd, "udp", 0).(*scenario.UDPFields)
	revOuter := layerAt(rev, "udp", 0).(*scenario.UDPFields)
	if fwdOuter.SPort != 51000 || revOuter.SPort != 51000 ||
		fwdOuter.DPort != 4789 || revOuter.DPort != 4789 {
		t.Errorf("outer(隧道)UDP 端口两向应均为声明值 51000->4789,得到 %d->%d / %d->%d",
			fwdOuter.SPort, fwdOuter.DPort, revOuter.SPort, revOuter.DPort)
	}
	fwdInner := layerAt(fwd, "udp", 1).(*scenario.UDPFields)
	revInner := layerAt(rev, "udp", 1).(*scenario.UDPFields)
	if fwdInner.SPort != 5300 || fwdInner.DPort != 53 {
		t.Errorf("上行 inner(会话)UDP 端口=%d->%d,期望声明值 5300->53", fwdInner.SPort, fwdInner.DPort)
	}
	if revInner.SPort != 53 || revInner.DPort != 5300 {
		t.Errorf("下行 inner(会话)UDP 端口=%d->%d,期望交换为 53->5300", revInner.SPort, revInner.DPort)
	}
	// VNI 两向不变。
	fwdVX := layerAt(fwd, "vxlan", 0).(*scenario.VXLANFields)
	revVX := layerAt(rev, "vxlan", 0).(*scenario.VXLANFields)
	if fwdVX.VNI != 100 || revVX.VNI != 100 {
		t.Errorf("VNI 两向应均为 100,得到 %d/%d", fwdVX.VNI, revVX.VNI)
	}
	// inner eth/ip 照常反转。
	fwdInnerEth := layerAt(fwd, "eth", 1).(*scenario.EthFields)
	revInnerEth := layerAt(rev, "eth", 1).(*scenario.EthFields)
	if revInnerEth.Src != fwdInnerEth.Dst || revInnerEth.Dst != fwdInnerEth.Src {
		t.Errorf("反向 inner eth 未交换")
	}
}
