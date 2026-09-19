package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
	"gopkg.in/yaml.v3"
)

// 本文件覆盖 mtu 自动分片的校验面(硬错)与告警面(软告警),对应 mtu.go:
//   - 两层 IP 同写 mtu 互斥、mtu × 覆盖字段(total_length/header_length/checksum/payload_length)互斥;
//   - mtu 结构下限(IPv4 头+8 / IPv6 主头+Fragment 头+8);
//   - quote_from 引用环(自引/互引/三包环,含 quote.stack 内嵌边)DFS 拦截,单向引用放行;
//   - quote.stack 内禁写 mtu;
//   - flow.stack 写 mtu 放行(展开器带到每个展开包),两层 IP 同写 mtu 仍报硬错;
//   - ipv4/ipv6 mtu 低于 RFC 下限(68/1280)产软告警,≥ 下限无告警。

// mtuPacket 构造一个单包场景。
func mtuPacket(layers ...scenario.Layer) *scenario.Scenario {
	return &scenario.Scenario{Packets: []scenario.Packet{{Stack: layers}}}
}

// mtuEth 是测试公用的以太层。
var mtuEth = scenario.Layer{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}}

// mtuUDPDns 是 53 端口 UDP 层(数据报载荷,分片典型载体)。
func mtuUDPDns() scenario.Layer {
	return scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53}}
}

// hexPtr 复用 checksum_test.go 的同名 helper(签名一致,包内共享)。

// TestMTUValidate 通过的形态:单层 IP 层写合法 mtu、隧道内层写 mtu、结构下限边界值。
func TestMTUValidate(t *testing.T) {
	cases := []struct {
		name  string
		stack []scenario.Layer
	}{
		{"ipv4 mtu 1500", []scenario.Layer{
			mtuEth,
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 1500}},
			mtuUDPDns(),
		}},
		{"ipv6 mtu 1500", []scenario.Layer{
			mtuEth,
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 1500}},
			mtuUDPDns(),
		}},
		{"两层 IP 只写一层 mtu(隧道)", []scenario.Layer{
			mtuEth,
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
			{Type: "gre", Fields: &scenario.GREFields{}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2", MTU: 1400}},
			mtuUDPDns(),
		}},
		{"mtu 恰等于结构下限 ipv4=28", []scenario.Layer{
			mtuEth,
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 28}},
			mtuUDPDns(),
		}},
		{"mtu 恰等于结构下限 ipv6=56", []scenario.Layer{
			mtuEth,
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 56}},
			mtuUDPDns(),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := scenario.Validate(mtuPacket(c.stack...)); err != nil {
				t.Fatalf("合法场景应通过校验,实际失败: %v", err)
			}
		})
	}
}

// TestMTUValidateRejects 硬错:两层 IP 同写 mtu、mtu × 覆盖字段互斥、结构下限。
func TestMTUValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		stack []scenario.Layer
		want  string
	}{
		{
			name: "两层 ipv4 同写 mtu",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2", MTU: 1500}},
				{Type: "gre", Fields: &scenario.GREFields{}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2", MTU: 1400}},
				mtuUDPDns(),
			},
			want: "两层 IP 同时写 mtu",
		},
		{
			name: "ipv4 mtu × total_length",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 1500, Length: hexPtr(9999)}},
				mtuUDPDns(),
			},
			want: "total_length",
		},
		{
			name: "ipv4 mtu × header_length",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 1500, IHL: hexPtr(5)}},
				mtuUDPDns(),
			},
			want: "header_length",
		},
		{
			name: "ipv4 mtu × checksum",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 1500, Checksum: hexPtr(0xdead)}},
				mtuUDPDns(),
			},
			want: "checksum",
		},
		{
			name: "ipv6 mtu × payload_length",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 1500, PayloadLength: hexPtr(9999)}},
				mtuUDPDns(),
			},
			want: "payload_length",
		},
		{
			name: "ipv4 mtu 27 低于结构下限",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 27}},
				mtuUDPDns(),
			},
			want: "结构下限",
		},
		{
			name: "ipv6 mtu 55 低于结构下限",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 55}},
				mtuUDPDns(),
			},
			want: "结构下限",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := scenario.Validate(mtuPacket(c.stack...))
			if err == nil {
				t.Fatal("应拒绝该场景,实际通过")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息应包含 %q,得到: %v", c.want, err)
			}
		})
	}
}

// TestMTUBelowMinimumWarning 软告警:ipv4 mtu < 68 / ipv6 mtu < 1280 照常通过校验,
// 只产对应 Code 的告警;≥ 下限则无 mtu 告警。
func TestMTUBelowMinimumWarning(t *testing.T) {
	cases := []struct {
		name     string
		stack    []scenario.Layer
		wantCode string // 空 = 不应产生 mtu 告警
	}{
		{
			name: "ipv4 mtu 67",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 67}},
				mtuUDPDns(),
			},
			wantCode: "ipv4.mtu-below-minimum",
		},
		{
			name: "ipv6 mtu 1279",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 1279}},
				mtuUDPDns(),
			},
			wantCode: "ipv6.mtu-below-minimum",
		},
		{
			name: "ipv4 mtu 68 不告警",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 68}},
				mtuUDPDns(),
			},
			wantCode: "",
		},
		{
			name: "ipv6 mtu 1280 不告警",
			stack: []scenario.Layer{
				mtuEth,
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", MTU: 1280}},
				mtuUDPDns(),
			},
			wantCode: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := scenario.Validate(mtuPacket(c.stack...)); err != nil {
				t.Fatalf("低于 RFC 下限是软告警,不应硬错: %v", err)
			}
			ws := scenario.Warnings(mtuPacket(c.stack...))
			for _, w := range ws {
				isMTU := strings.Contains(w.Code, "mtu-below-minimum")
				if c.wantCode == "" {
					if isMTU {
						t.Errorf("不应产生 mtu-below-minimum 告警,得到: %v", w)
					}
					continue
				}
				if w.Code == c.wantCode {
					if !strings.Contains(w.Path, ".mtu") {
						t.Errorf("告警 Path 应指向 .mtu 字段,得到 %q", w.Path)
					}
					return
				}
			}
			if c.wantCode != "" {
				t.Errorf("应产生告警 %s,得到 %v", c.wantCode, ws)
			}
		})
	}
}

// mtuICMP 构造一个 ICMPv4 错误报文层(destination_unreachable / fragmentation_needed)。
func mtuICMP(quoteFrom string) scenario.Layer {
	return scenario.Layer{Type: "icmp", Fields: &scenario.ICMPFields{
		Type:      yaml.Node{Kind: yaml.ScalarNode, Value: "destination_unreachable"},
		Code:      yaml.Node{Kind: yaml.ScalarNode, Value: "fragmentation_needed"},
		QuoteFrom: quoteFrom,
	}}
}

// TestQuoteFromCycle quote_from 引用环(自引/互引/三包环)在校验期被 DFS 拦下,
// 而不是构建期无限递归栈溢出;合法单向引用不受影响。
func TestQuoteFromCycle(t *testing.T) {
	ip := scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}}
	pkt := func(name string, layers ...scenario.Layer) scenario.Packet {
		return scenario.Packet{Name: name, Stack: append([]scenario.Layer{mtuEth, ip}, layers...)}
	}
	cases := []struct {
		name    string
		packets []scenario.Packet
		wantErr string // 空 = 应通过
	}{
		{
			name:    "自引",
			packets: []scenario.Packet{pkt("self", mtuICMP("self"))},
			wantErr: "self → self",
		},
		{
			name: "两包互引",
			packets: []scenario.Packet{
				pkt("a", mtuICMP("b")),
				pkt("b", mtuICMP("a")),
			},
			wantErr: "a → b → a",
		},
		{
			name: "三包环",
			packets: []scenario.Packet{
				pkt("a", mtuICMP("b")),
				pkt("b", mtuICMP("c")),
				pkt("c", mtuICMP("a")),
			},
			wantErr: "引用环",
		},
		{
			name: "单向引用合法",
			packets: []scenario.Packet{
				pkt("big", mtuUDPDns()),
				pkt("icmp", mtuICMP("big")),
			},
			wantErr: "",
		},
		{
			name: "环外无关包不受影响",
			packets: []scenario.Packet{
				pkt("plain", mtuUDPDns()),
				pkt("a", mtuICMP("b")),
				pkt("b", mtuICMP("a")),
			},
			wantErr: "引用环",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: c.packets}
			err := scenario.Validate(s)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("单向引用应通过校验,实际失败: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("引用环应被拒绝,实际通过")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("错误信息应包含 %q,得到: %v", c.wantErr, err)
			}
		})
	}
}

// TestQuoteStackMTURejected quote.stack 内的 ipv4/ipv6 层写 mtu → 硬错:
// quote 是载荷提取视图,不是上线的包,对它分片无语义。
func TestQuoteStackMTURejected(t *testing.T) {
	ip := scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}}
	icmpWithQuote := scenario.Layer{Type: "icmp", Fields: &scenario.ICMPFields{
		Type: yaml.Node{Kind: yaml.ScalarNode, Value: "destination_unreachable"},
		Code: yaml.Node{Kind: yaml.ScalarNode, Value: "fragmentation_needed"},
		Quote: &scenario.Packet{Stack: []scenario.Layer{
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.9", Dst: "10.0.0.10", MTU: 1500}},
			mtuUDPDns(),
		}},
	}}
	s := mtuPacket(mtuEth, ip, icmpWithQuote)
	err := scenario.Validate(s)
	if err == nil {
		t.Fatal("quote.stack 内写 mtu 应被拒绝,实际通过")
	}
	for _, want := range []string{"quote", "mtu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应包含 %q,得到: %v", want, err)
		}
	}
}

// TestFlowStackMTUAllowed flow.stack 写 mtu 放行:flow 展开器把 ipv4 字段带到每个
// 展开包,mtu 随之生效;合法值不产任何 mtu 相关告警。
func TestFlowStackMTUAllowed(t *testing.T) {
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{{
		Name: "dns-big",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80", MTU: 1500}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 49152, DPort: 53}},
			{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
		},
		Messages: []scenario.Message{
			{From: "src", Stack: []scenario.Layer{
				{Type: "dns", Fields: &scenario.DNSFields{
					ID:        1,
					Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
				}},
			}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("flow.stack 写 mtu 应放行,实际失败: %v", err)
	}
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w.Code, "mtu") {
			t.Errorf("flow 合法 mtu 不应产告警,得到: %v", w)
		}
	}
}

// TestFlowStackDoubleMTURejected flow.stack(VXLAN 内外两段)两层 IP 同写 mtu 报硬错:
// builder 的分片目标层只认一层,后层会静默覆盖前层 —— 与 standalone packets 同规则,
// 校验期统一拦截。
func TestFlowStackDoubleMTURejected(t *testing.T) {
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{{
		Name: "vxlan-double-mtu",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", MTU: 100}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 4789, DPort: 4789}},
			{Type: "vxlan", Fields: &scenario.VXLANFields{}},
			{Type: "eth", Fields: &scenario.EthFields{Src: "aa:bb:cc:dd:ee:01", Dst: "aa:bb:cc:dd:ee:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2", MTU: 80}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
		},
		Messages: []scenario.Message{
			{From: "src", Stack: []scenario.Layer{
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "hello"}},
			}},
		},
	}}}
	err := scenario.Validate(s)
	if err == nil {
		t.Fatalf("flow.stack 两层 IP 同写 mtu 应报硬错,实际放行")
	}
	want := "同一 stack 内两层 IP 同时写 mtu"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("错误信息应包含 %q,得到: %v", want, err)
	}
}

// TestQuoteFromNestedCycleDetect: quote.stack 内嵌的 quote_from 也构成依赖边。
// 自引环(a 的 quote 里内嵌 icmp 再 quote_from: a)与两包互引均须在校验期拦截,
// 不能拖到构建期才以"前向引用"口径失败 —— 那个报错指引(调整声明顺序)修不了环。
func TestQuoteFromNestedCycleDetect(t *testing.T) {
	// 自引:packet a 的 quote.stack 内嵌 icmp 引用 a 自身。
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Name: "a",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "icmp", Fields: &scenario.ICMPFields{
				Quote: &scenario.Packet{Stack: []scenario.Layer{
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.2", Dst: "10.0.0.1"}},
					{Type: "icmp", Fields: &scenario.ICMPFields{QuoteFrom: "a"}},
				}},
			}},
		},
	}}}
	if err := scenario.Validate(s); err == nil {
		t.Fatalf("quote.stack 内嵌的自引环应在校验期拦截")
	} else if want := "quote_from 引用环"; !strings.Contains(err.Error(), want) {
		t.Errorf("错误信息应包含 %q,得到: %v", want, err)
	}

	// 两包互引:b 顶层 quote_from a,a 的 quote.stack 内嵌 icmp quote_from b。
	inner := scenario.Packet{
		Name: "b",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "icmp", Fields: &scenario.ICMPFields{QuoteFrom: "a"}},
		},
	}
	s2 := &scenario.Scenario{Packets: []scenario.Packet{{
		Name: "a",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "icmp", Fields: &scenario.ICMPFields{
				Quote: &scenario.Packet{Stack: []scenario.Layer{
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.2", Dst: "10.0.0.1"}},
					{Type: "icmp", Fields: &scenario.ICMPFields{QuoteFrom: "b"}},
				}},
			}},
		},
	}}}
	s2.Packets = append(s2.Packets, inner)
	err := scenario.Validate(s2)
	if err == nil {
		t.Fatalf("跨包嵌套互引环应在校验期拦截")
	}
	if want := "quote_from 引用环"; !strings.Contains(err.Error(), want) {
		t.Errorf("错误信息应包含 %q,得到: %v", want, err)
	}
}
