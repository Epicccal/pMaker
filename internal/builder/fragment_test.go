package builder_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 ipv4/ipv6 的 mtu 自动分片:
// 切块边界(恰等于 mtu / 差 1 字节 / 8 字节对齐)、确定性 ID 分配、分片同刻、
// IPv6 Fragment 扩展头、未分片不消耗计数器、quote_from×mtu 的记忆化取材。

// buildMTUOut 构造 eth+ipv4(mtu)+udp+payload 场景并出包:载荷 16 字节。
func buildMTUOut(t *testing.T, mtu int) ([]builder.OutPacket, error) {
	t.Helper()
	src := `
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.1", ttl: 64, mtu: ` + strconv.Itoa(mtu) + ` }
      - udp:  { sport: 40000, dport: 65001 }
      - payload: { payload: "0123456789012345" }
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		return nil, err
	}
	return buildPackets(s)
}

// TestMTUFragmentBoundary 切块边界:数据报(20 头 + 8 UDP + 16 载荷 = 44)
// 恰好等于 mtu=44 → 不分片;mtu=43 差 1 字节 → 分片;mtu=36 → 块 16 → 2 片。
func TestMTUFragmentBoundary(t *testing.T) {
	out, err := buildMTUOut(t, 44)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Frag.N != 1 {
		t.Fatalf("mtu=44 恰好容纳,应 1 包,得到 %d(Frag=%+v)", len(out), out[0].Frag)
	}

	out, err = buildMTUOut(t, 43)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("mtu=43 应 2 片,得到 %d 包", len(out))
	}

	out, err = buildMTUOut(t, 36)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("mtu=36 应 2 片,得到 %d", len(out))
	}
	for i, o := range out {
		if o.Frag.N != 2 || o.Frag.K != i {
			t.Fatalf("片 %d: Frag=%+v", i, o.Frag)
		}
	}
}

// TestMTUFragmentIPv4Fields 验证分片逐片的 IPv4 头:ID 一致、MF 位、偏移 8 字节
// 单位、末片 MF=0。载荷 24 字节(UDP+16)、mtu=28 → 块 8 → 3 片。
func TestMTUFragmentIPv4Fields(t *testing.T) {
	out, err := buildMTUOut(t, 28)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("应 3 片,得到 %d", len(out))
	}
	for k, o := range out {
		pkt := gopacket.NewPacket(o.Data, layers.LayerTypeEthernet, gopacket.Default)
		l := pkt.Layer(layers.LayerTypeIPv4)
		if l == nil {
			t.Fatalf("片 %d 未解析出 IPv4", k)
		}
		ip := l.(*layers.IPv4)
		if ip.Id != 1 {
			t.Fatalf("片 %d: Id=%d,应 1(确定性计数器首个值)", k, ip.Id)
		}
		wantMF := k < len(out)-1
		if (ip.Flags & layers.IPv4MoreFragments) != 0 != wantMF {
			t.Fatalf("片 %d: MF=%v,应 %v", k, ip.Flags&layers.IPv4MoreFragments != 0, wantMF)
		}
		if ip.FragOffset != uint16(k) { // 块 8 字节 = 每片 1 个偏移单位
			t.Fatalf("片 %d: FragOffset=%d,应 %d", k, ip.FragOffset, k)
		}
	}
}

// TestMTUFragmentSameTime 验证各片与原包同刻(分片不引入额外时间步进)。
func TestMTUFragmentSameTime(t *testing.T) {
	out, err := buildMTUOut(t, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 2 {
		t.Fatalf("mtu=30 应分片,得到 %d", len(out))
	}
	for i, o := range out {
		if !o.Time.Equal(out[0].Time) {
			t.Fatalf("片 %d 时间 %v ≠ 首片 %v", i, o.Time, out[0].Time)
		}
	}
}

// TestMTUIPv6FragmentHeader 验证 IPv6 分片插入 Fragment 扩展头:NextHeader=UDP(17)
// 移入扩展头;主头 next_header=44;gopacket 回读停在 Fragment 层。
func TestMTUIPv6FragmentHeader(t *testing.T) {
	src := `
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv6: { src: "2001:db8::1", dst: "2001:db8::2", hop_limit: 64, mtu: 64 }
      - udp:  { sport: 40000, dport: 65001 }
      - payload: { payload: "0123456789abcdef0123456789abcdef" }
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildPackets(s)
	if err != nil {
		t.Fatal(err)
	}
	// 块 = (64-40-8)&^7 = 16;载荷 32 + UDP 头 8 = 40 字节数据报 → 3 片。
	if len(out) != 3 {
		t.Fatalf("应 3 片,得到 %d", len(out))
	}
	for k, o := range out {
		pkt := gopacket.NewPacket(o.Data[14:], layers.LayerTypeIPv6, gopacket.Default)
		fragL := pkt.Layer(layers.LayerTypeIPv6Fragment)
		if fragL == nil {
			t.Fatalf("片 %d 未解析出 IPv6Fragment: %v", k, pkt.ErrorLayer())
		}
		frag := fragL.(*layers.IPv6Fragment)
		if frag.NextHeader != layers.IPProtocolUDP {
			t.Fatalf("片 %d: Fragment.NextHeader=%v,应 UDP(17)", k, frag.NextHeader)
		}
		wantMF := k < len(out)-1
		if frag.MoreFragments != wantMF {
			t.Fatalf("片 %d: M=%v,应 %v", k, frag.MoreFragments, wantMF)
		}
		if frag.FragmentOffset != uint16(k)*2 { // 块 16 字节 = 每片 2 个偏移单位
			t.Fatalf("片 %d: Offset=%d", k, frag.FragmentOffset)
		}
	}
}

// TestMTUIDCounterNotConsumedUnfragmented 验证未分片的包不消耗 ID 计数器。
func TestMTUIDCounterNotConsumedUnfragmented(t *testing.T) {
	src := `
link_type: raw
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", mtu: 40 }
      - udp:  { sport: 1, dport: 2 }
      - payload: { payload: "0123456789012345678901234567890123456789" } # 40 字节,超限
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 3, dport: 4 }
      - payload: { payload: "small" }
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildPackets(s)
	if err != nil {
		t.Fatal(err)
	}
	// 第 1 包:数据报 = 8(UDP)+ 40 = 48 > 40 → 分片,块 (40-20)&^7=16 → 3 片。
	// 第 2 包未分片,ID 保持缺省 0。
	last := out[len(out)-1]
	pkt := gopacket.NewPacket(last.Data, layers.LayerTypeIPv4, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Id != 0 {
		t.Fatalf("未分片包 Id=%d,应 0(计数器未被无关包消耗)", ip.Id)
	}
}

// TestMTUQuoteFromMemoizedID 验证 quote_from 记忆化:被引包分片后,quote 字节与
// pcap 首片的 ip-down 段逐字节一致(含计数器分配的 ID)。
func TestMTUQuoteFromMemoizedID(t *testing.T) {
	src := `
link_type: raw
packets:
  - name: probe
    stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", mtu: 40 }
      - udp:  { sport: 1, dport: 2 }
      - payload: { payload: "0123456789012345678901234567890123456789" }
  - stack:
      - ipv4: { src: "10.0.0.2", dst: "10.0.0.1" }
      - icmp:
          type: destination_unreachable
          code: 4
          quote_from: probe
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildPackets(s)
	if err != nil {
		t.Fatal(err)
	}
	// probe 分片的首片 id 应为 1;ICMP quote 内嵌的 IP 头 Id 应与首片一致。
	frag0 := gopacket.NewPacket(out[0].Data, layers.LayerTypeIPv4, gopacket.Default)
	f0 := frag0.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if f0.Id != 1 {
		t.Fatalf("首片 Id=%d,应 1", f0.Id)
	}
	// 最后一个 out 包是 ICMP 报文:RFC 792 quote = IP 头(20)+ 8 字节 UDP 头。
	icmpPkt := gopacket.NewPacket(out[len(out)-1].Data, layers.LayerTypeIPv4, gopacket.Default)
	icmpL := icmpPkt.Layer(layers.LayerTypeICMPv4)
	if icmpL == nil {
		t.Fatal("未解析出 ICMP")
	}
	icmp := icmpL.(*layers.ICMPv4)
	quote := icmp.Payload
	if len(quote) < 28 {
		t.Fatalf("quote 过短: %d", len(quote))
	}
	for i := 0; i < 20; i++ {
		if quote[i] != out[0].Data[i] {
			t.Fatalf("quote 字节 %d 不一致: %02x ≠ %02x", i, quote[i], out[0].Data[i])
		}
	}
}

// TestMTUFlowFieldsNotPolluted 验证分片器不回写 scenario Fields:flow 模板的
// Fields 指针跨包共享,mtu 分片的计数器 ID 只进分片器自建副本,不泄漏进
// 同 flow 后续展开包(未分片包 id 恒 0)。
func TestMTUFlowFieldsNotPolluted(t *testing.T) {
	src := `
link_type: raw
flows:
  - name: f
    stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", mtu: 40 }
      - udp:  { sport: 1, dport: 2 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - payload: { payload: "0123456789012345678901234567890123456789" } # 40 字节,超限
      - from: dst
        stack:
          - payload: { payload: "ok" }
      - from: src
        stack:
          - payload: { payload: "second" }
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildPackets(s)
	if err != nil {
		t.Fatal(err)
	}
	// 第 1 条消息(40 字节载荷 + 8 UDP 头 = 48 数据报)分片;最后一条消息(6 字节)
	// 不分片。若 ID 回写进共享 Fields,后续包会带上非 0 的 id。
	last := out[len(out)-1]
	pkt := gopacket.NewPacket(last.Data, layers.LayerTypeIPv4, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Id != 0 {
		t.Fatalf("flow 后续未分片包 Id=%d,应 0(Fields 未被污染)", ip.Id)
	}
}

// TestMTUQuoteFromForwardReference 验证前向引用硬错:被引 packet 排在引用包之后
// (此刻尚未构建、记忆化未命中)必须报错,不得静默二次序列化。
func TestMTUQuoteFromForwardReference(t *testing.T) {
	src := `
link_type: raw
packets:
  - stack:
      - ipv4: { src: "10.0.0.2", dst: "10.0.0.1" }
      - icmp:
          type: destination_unreachable
          code: 4
          quote_from: probe
  - name: probe
    stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 1, dport: 2 }
      - payload: { payload: "x" }
`
	s, err := scenario.Parse([]byte(src), ".")
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildPackets(s)
	if err == nil {
		t.Fatal("前向引用应硬错")
	}
	if got := err.Error(); !strings.Contains(got, "前向引用") {
		t.Fatalf("报错应含「前向引用」: %s", got)
	}
}

// TestMTUDatagramTooLarge 验证数据报超过片偏移 13 位 + 长度 16 位上限时硬错,
// 而不是切出越界片。
func TestMTUDatagramTooLarge(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "raw",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 28}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: strings.Repeat("x", 66000)}},
			},
		}},
	}
	_, err := buildPackets(s)
	if err == nil {
		t.Fatal("66000 字节数据报超出 IPv4 分片上限,应硬错")
	}
	if got := err.Error(); !strings.Contains(got, "数据报过大无法分片") {
		t.Fatalf("报错应含「数据报过大无法分片」: %s", got)
	}
}
