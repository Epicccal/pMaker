package golden_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/ip6defrag"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 mtu 自动分片的 golden 断言:
// 5 个示例的基准 pcap 由 TestExamplesGolden 锁定;这里额外断言:
//   - gopacket 回读分片包只到 Fragment 层(IPv4/IPv6 同口径);
//   - 逐片 proto 保持原 L4 协议号(UDP=17 / GRE=47)
//     (锁定目标层对象复用,防回退成按层名重推导落 TCP 缺省);
//   - quote_from 引分片包:quote 内嵌 IP 头与 wire 首片逐字节一致。

// readGoldenIPFrag 回读示例 pcap 的 IPv4 层列表(去掉 eth 头)。
func readGoldenIPFrag(t *testing.T, example string) []*layers.IPv4 {
	t.Helper()
	data := generatePcap(t, "../../examples/ip_fragment/"+example+".yaml")
	pkts := readPackets(t, data)
	out := make([]*layers.IPv4, 0, len(pkts))
	for _, p := range pkts {
		l := p.Layer(layers.LayerTypeIPv4)
		if l == nil {
			t.Fatalf("%s: 未解析出 IPv4", example)
		}
		out = append(out, l.(*layers.IPv4))
	}
	return out
}

// TestIPFragIPv4Golden: big-udp 分 2 片,small-udp 未分片;逐片 Id 一致、MF 递减、
// 偏移按块推进;末片 MF=0;未分片 id=0。块 = (44-20)&^7 = 24,inner = 8+29 = 37
// 字节 → 2 片(24+13),第二片偏移 24/8 = 3。
func TestIPFragIPv4Golden(t *testing.T) {
	ips := readGoldenIPFrag(t, "ipv4_mtu")
	if len(ips) != 3 {
		t.Fatalf("应 3 个 IPv4 包(2 片 + 1 未分片),得到 %d", len(ips))
	}
	for k, wantMF := range []bool{true, false} {
		ip := ips[k]
		if ip.Id != 1 {
			t.Errorf("片 %d: Id=%d,应 1", k, ip.Id)
		}
		wantFlags := layers.IPv4Flag(0)
		if wantMF {
			wantFlags = layers.IPv4MoreFragments
		}
		if ip.Flags != wantFlags {
			t.Errorf("片 %d: Flags=%v,应 %v", k, ip.Flags, wantFlags)
		}
		if ip.FragOffset != uint16(k)*3 { // 块 24 字节 = 3 个偏移单位
			t.Errorf("片 %d: FragOffset=%d", k, ip.FragOffset)
		}
	}
	if ips[2].Id != 0 {
		t.Errorf("未分片包 Id=%d,应 0", ips[2].Id)
	}
}

// TestIPFragIPv6Golden: IPv6 分片逐片断言 Fragment 扩展头:NextHeader=UDP、
// M 位、偏移;gopacket 回读停在 Fragment 层(L4 不逐片解码)。
func TestIPFragIPv6Golden(t *testing.T) {
	data := generatePcap(t, "../../examples/ip_fragment/ipv6_mtu.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("应 3 片,得到 %d", len(pkts))
	}
	for k, p := range pkts {
		fragL := p.Layer(layers.LayerTypeIPv6Fragment)
		if fragL == nil {
			t.Fatalf("片 %d 未解析出 IPv6Fragment", k)
		}
		frag := fragL.(*layers.IPv6Fragment)
		if frag.NextHeader != layers.IPProtocolUDP {
			t.Errorf("片 %d: Fragment.NextHeader=%v,应 UDP", k, frag.NextHeader)
		}
		if frag.MoreFragments != (k < 2) {
			t.Errorf("片 %d: M=%v", k, frag.MoreFragments)
		}
		if frag.FragmentOffset != uint16(k)*2 {
			t.Errorf("片 %d: Offset=%d", k, frag.FragmentOffset)
		}
		if p.Layer(layers.LayerTypeUDP) != nil {
			t.Errorf("片 %d: 分片包不应逐片解码出 UDP", k)
		}
	}
}

// TestIPFragProtoPerFragment: 分片包逐片 proto 保持原 L4 协议号(UDP=17),
// 锁定分片重建用目标层对象快照、不按层名重推导(否则会落 TCP=6 缺省)。
func TestIPFragProtoPerFragment(t *testing.T) {
	ips := readGoldenIPFrag(t, "udp_flow_dns_mtu")
	if len(ips) != 3 {
		t.Fatalf("flow DNS 场景应 3 个 IPv4 包(查询 + 响应 2 片),得到 %d", len(ips))
	}
	for k, ip := range ips {
		if ip.Protocol != layers.IPProtocolUDP {
			t.Errorf("包 %d: Protocol=%v,应 UDP(17)", k, ip.Protocol)
		}
	}
	// 查询包未分片 id=0;响应分片共用计数器 ID。
	if ips[0].Id != 0 {
		t.Errorf("查询包 Id=%d,应 0", ips[0].Id)
	}
	if ips[1].Id == 0 || ips[2].Id != ips[1].Id {
		t.Errorf("响应分片 Id 应一致非 0:%d / %d", ips[1].Id, ips[2].Id)
	}
}

// TestIPFragQuoteFromGolden: icmp_quote_from_mtu 的 quote 内嵌 IP 头与 wire
// 首片逐字节一致(记忆化取材,含分片 ID)。块 = 24,inner = 8+40 = 48 字节 →
// 2 片,加 1 个 ICMP 共 3 包。
func TestIPFragQuoteFromGolden(t *testing.T) {
	data := generatePcap(t, "../../examples/ip_fragment/icmp_quote_from_mtu.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("应 3 包(2 片 + 1 ICMP),得到 %d", len(pkts))
	}
	first := pkts[0].Layer(layers.LayerTypeIPv4)
	if first == nil {
		t.Fatal("首片未解析出 IPv4")
	}
	icmpL := pkts[2].Layer(layers.LayerTypeICMPv4)
	if icmpL == nil {
		t.Fatal("末包未解析出 ICMP")
	}
	quote := icmpL.(*layers.ICMPv4).Payload
	if len(quote) < 28 {
		t.Fatalf("quote 过短: %d", len(quote))
	}
	firstBytes := first.(*layers.IPv4).LayerContents()
	for i := range 20 {
		if quote[i] != firstBytes[i] {
			t.Fatalf("quote 字节 %d 不一致: %02x ≠ %02x", i, quote[i], firstBytes[i])
		}
	}
}

// TestIPFragGREInnerGolden: GRE 内层分片,外层 IP 逐片存在且 proto=GRE(47)。
func TestIPFragGREInnerGolden(t *testing.T) {
	ips := readGoldenIPFrag(t, "gre_inner_mtu")
	if len(ips) != 2 {
		t.Fatalf("GRE 内层分片应 2 个外层 IPv4 包,得到 %d", len(ips))
	}
	for k, ip := range ips {
		if ip.Protocol != layers.IPProtocolGRE {
			t.Errorf("外层包 %d: Protocol=%v,应 GRE(47)", k, ip.Protocol)
		}
	}
}

// TestIPFragIPv4Reassembly: ip4defrag 重组 ipv4_mtu 的 2 片,数据报载荷与
// 同一场景去掉 mtu 直接构建的结果逐字节一致 —— 分片不丢不错一个字节。
func TestIPFragIPv4Reassembly(t *testing.T) {
	ips := readGoldenIPFrag(t, "ipv4_mtu")
	defrag := ip4defrag.NewIPv4Defragmenter()
	var assembled *layers.IPv4
	for _, ip := range ips[:2] {
		got, err := defrag.DefragIPv4WithTimestamp(ip, time.Time{})
		if err != nil {
			t.Fatalf("defrag: %v", err)
		}
		if got != nil {
			assembled = got
		}
	}
	if assembled == nil {
		t.Fatal("分片未完成重组")
	}
	if assembled.Protocol != layers.IPProtocolUDP {
		t.Fatalf("重组后 Protocol=%v,应 UDP", assembled.Protocol)
	}

	// 参照:同一 stack 去掉 mtu 直接构建,取其 IP 载荷(UDP 头 + payload)。
	s, err := scenario.Load("../../examples/ip_fragment/ipv4_mtu.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range s.Packets[0].Stack {
		if f, ok := l.Fields.(*scenario.IPv4Fields); ok {
			f.MTU = 0
		}
	}
	ref := readPackets(t, generatePcapScenario(t, s))
	refIP := ref[0].Layer(layers.LayerTypeIPv4)
	if refIP == nil {
		t.Fatal("参照包未解析出 IPv4")
	}
	want := refIP.(*layers.IPv4).LayerPayload()
	got := assembled.LayerPayload()
	if !bytes.Equal(got, want) {
		t.Fatalf("重组载荷与未分片构建不一致(%d vs %d 字节)", len(got), len(want))
	}
}

// TestIPFragIPv6Reassembly: ip6defrag 重组 ipv6_mtu 的 3 片(UDP 分片在
// DefragIPv6 的支持范围内),重组结果重新序列化后与未分片构建的数据报比对。
func TestIPFragIPv6Reassembly(t *testing.T) {
	data := generatePcap(t, "../../examples/ip_fragment/ipv6_mtu.yaml")
	pkts := readPackets(t, data)
	defrag := ip6defrag.NewIPv6Defragmenter()
	var assembled *layers.IPv6
	for _, p := range pkts {
		ipL := p.Layer(layers.LayerTypeIPv6)
		fgL := p.Layer(layers.LayerTypeIPv6Fragment)
		if ipL == nil || fgL == nil {
			t.Fatal("分片包应同时含 IPv6 与 Fragment 层")
		}
		if got := defrag.DefragIPv6(ipL.(*layers.IPv6), fgL.(*layers.IPv6Fragment)); got != nil {
			assembled = got
		}
	}
	if assembled == nil {
		t.Fatal("分片未完成重组")
	}

	// 参照:同一 stack 去掉 mtu 直接构建。
	s, err := scenario.Load("../../examples/ip_fragment/ipv6_mtu.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range s.Packets[0].Stack {
		if f, ok := l.Fields.(*scenario.IPv6Fields); ok {
			f.MTU = 0
		}
	}
	ref := readPackets(t, generatePcapScenario(t, s))
	refIP := ref[0].Layer(layers.LayerTypeIPv6)
	if refIP == nil {
		t.Fatal("参照包未解析出 IPv6")
	}
	// 重组返回的是解码层对象(非 wire 字节):比较双方都取「IPv6 载荷」口径,
	// 即 UDP 头 + payload 字节,不比头本身。
	got := assembled.LayerPayload()
	want := refIP.(*layers.IPv6).LayerPayload()
	if !bytes.Equal(got, want) {
		t.Fatalf("重组载荷与未分片构建不一致(%d vs %d 字节)", len(got), len(want))
	}
}
