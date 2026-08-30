package golden_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 length 覆盖(两态语义)的端到端用例:自动计算 vs 显式覆盖。
// 畸形用例(显式覆盖撒谎值)只断言 wire 字段值,不做 gopacket 结构回读断言 ——
// 长度撒谎的包按定义无法被正确重组(见 ip4.go DecodeFromBytes 对 Length<20/IHL<5 的拦截),
// 这是与 checksum 覆盖不同的约束(错误 checksum 不影响解析结构)。

func TestIPv4LengthOverride(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/ipv4/bad_length.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// ① 规范包:total_length 自动 = 20(ip 头)+ 20(tcp 头)= 40,ihl=5。
	auto := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if auto.Length != 40 {
		t.Fatalf("① 规范包 ipv4 total_length = %d,期望 40(自动计算)", auto.Length)
	}
	if auto.IHL != 5 {
		t.Fatalf("① 规范包 ipv4 header_length = %d,期望 5(自动计算)", auto.IHL)
	}

	// ② 畸形包:total_length 原样落 9999,ihl 未写仍补成 5(公式值,不归零)。
	bad := pkts[1].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if bad.Length != 9999 {
		t.Fatalf("② 畸形包 ipv4 total_length = %d,期望 9999(显式覆盖原样落值)", bad.Length)
	}
	if bad.IHL != 5 {
		t.Fatalf("② 畸形包 ipv4 header_length = %d,期望 5(未覆盖应补公式值)", bad.IHL)
	}
}

func TestTCPDataOffsetOverride(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/tcp/bad_data_offset.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// ① 规范包:带 MSS option(4 字节,无 padding)→ header_length=6。
	auto := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if auto.DataOffset != 6 {
		t.Fatalf("① 规范包 tcp header_length = %d,期望 6(20+4 MSS,自动计算)", auto.DataOffset)
	}

	// ② 畸形包:header_length 原样落 15(0xF)。
	bad := pkts[1].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if bad.DataOffset != 15 {
		t.Fatalf("② 畸形包 tcp header_length = %d,期望 15(显式覆盖原样落值)", bad.DataOffset)
	}
}

func TestUDPLengthOverride(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/udp/bad_length.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// ① 规范包:total_length 自动 = 8(头)+ 5(payload) = 13。
	auto := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if auto.Length != 13 {
		t.Fatalf("① 规范包 udp total_length = %d,期望 13(自动计算)", auto.Length)
	}

	// ② 畸形包:total_length 原样落 1234。
	bad := pkts[1].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if bad.Length != 1234 {
		t.Fatalf("② 畸形包 udp total_length = %d,期望 1234(显式覆盖原样落值)", bad.Length)
	}
}

func TestIPv6PayloadLengthOverride(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/ipv6/bad_length.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// ① 规范包:payload_length 自动 = 8(udp 头)+ 5(payload) = 13(不含 40B ipv6 头)。
	auto := pkts[0].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if auto.Length != 13 {
		t.Fatalf("① 规范包 ipv6 payload_length = %d,期望 13(自动计算)", auto.Length)
	}

	// ② 畸形包:payload_length 原样落 9999。
	bad := pkts[1].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if bad.Length != 9999 {
		t.Fatalf("② 畸形包 ipv6 payload_length = %d,期望 9999(显式覆盖原样落值)", bad.Length)
	}
}
