package builder_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// dnsScenario 把一组 DNSFields 包成 eth/ipv4/udp/dns 单包场景,供回读测试使用。
func dnsScenario(d *scenario.DNSFields) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "8.8.8.8", TTL: u8ptr(64)}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 53000, DPort: 53}},
				{Type: "dns", Fields: d},
			},
		}},
	}
}

// buildDNSPackets 跑 build→write→回读,返回解析出的 DNS 层。
func buildDNSPackets(t *testing.T, d *scenario.DNSFields) []*layers.DNS {
	t.Helper()
	s := dnsScenario(d)
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out []*layers.DNS
	for _, p := range readPackets(t, buf.Bytes()) {
		if l := p.Layer(layers.LayerTypeDNS); l != nil {
			out = append(out, l.(*layers.DNS))
		}
	}
	if len(out) != 1 {
		t.Fatalf("期望 1 个 DNS 层,得到 %d", len(out))
	}
	return out
}

// buildDNSPacketsErr 跑 build 并断言返回错误(且错误链可校验)。
func buildDNSPacketsErr(t *testing.T, d *scenario.DNSFields, wantSub string) {
	t.Helper()
	s := dnsScenario(d)
	// 不强制 Validate:部分畸形 data(如非字符串 CNAME)需走到 build 才暴露。
	_ = scenario.Validate(s)
	_, err := builder.Build(s)
	if err == nil {
		t.Fatalf("期望 build 报错(含 %q),实际成功", wantSub)
	}
	if wantSub != "" && !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("build 错误 %q 不含 %q", err.Error(), wantSub)
	}
}

func scalarNode(v string) yaml.Node {
	return yaml.Node{Kind: yaml.ScalarNode, Value: v}
}

// TestDNSADCDFlagsEncoded 验证 AD/CD 标志写入 byte[3](RFC 4035 §2)。
func TestDNSADCDFlagsEncoded(t *testing.T) {
	cases := []struct {
		name      string
		ad        bool
		cd        bool
		wantZ     uint8 // 期望 gopacket 回读的 Z(bits6-4)
		wantByte3 uint8 // 期望 byte[3] 中 Z 段的位掩码
	}{
		{"none", false, false, 0x00, 0x00},
		{"ad", true, false, 0x02, 0x20},
		{"cd", false, true, 0x01, 0x10},
		{"ad+cd", true, true, 0x03, 0x30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &scenario.DNSFields{
				ID:                0x1234,
				QR:                "response",
				RCode:             "no_error",
				AuthenticatedData: tc.ad,
				CheckingDisabled:  tc.cd,
				Questions:         []scenario.DNSQuestionFields{{Name: "example.com.", Type: "A", Class: "IN"}},
				Answers:           []scenario.DNSRRFields{{Name: "example.com.", Type: "A", Class: "IN", TTL: 300, Data: scalarNode("93.184.216.34")}},
			}
			got := buildDNSPackets(t, d)[0]
			if got.Z != tc.wantZ {
				t.Fatalf("Z = %#x,期望 %#x", got.Z, tc.wantZ)
			}
			// byte[3] = RA(bit7) | Z(bits6-4) | RCODE(bits3-0)
			b3 := got.Contents[3]
			if b3&0x30 != tc.wantByte3 {
				t.Fatalf("byte[3] Z 段 = %#x,期望掩码 %#x(完整 byte[3]=%#x)", b3&0x30, tc.wantByte3, b3)
			}
			if b3&0x40 != 0 {
				t.Fatalf("RFC 4035 要求 Z 的 bit6 必须为 0,实际 byte[3]=%#x", b3)
			}
		})
	}
}

// TestDNSNameValidation 验证超长标签/超长整名在 build 时报错(A2)。
func TestDNSNameValidation(t *testing.T) {
	t.Run("label-too-long", func(t *testing.T) {
		d := &scenario.DNSFields{
			Questions: []scenario.DNSQuestionFields{{Name: strings.Repeat("a", 64) + ".example.com", Type: "A"}},
		}
		buildDNSPacketsErr(t, d, "超 63")
	})
	t.Run("name-too-long", func(t *testing.T) {
		// 128 个单字符标签:编码后 128*2+1 = 257 > 255
		d := &scenario.DNSFields{
			Questions: []scenario.DNSQuestionFields{{Name: strings.TrimRight(strings.Repeat("a.", 128), "."), Type: "A"}},
		}
		buildDNSPacketsErr(t, d, "超 255")
	})
	t.Run("empty-label", func(t *testing.T) {
		d := &scenario.DNSFields{
			Questions: []scenario.DNSQuestionFields{{Name: "example..com", Type: "A"}},
		}
		buildDNSPacketsErr(t, d, "空标签")
	})
}

// TestDNSCNAMENonStringErrors 验证 CNAME data 非字符串时报错而非退化为根域(A3)。
func TestDNSCNAMENonStringErrors(t *testing.T) {
	seq := yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "1", Tag: "!!int"},
	}}
	d := &scenario.DNSFields{
		Questions: []scenario.DNSQuestionFields{{Name: "a.example.com", Type: "A"}},
		Answers:   []scenario.DNSRRFields{{Name: "a.example.com", Type: "CNAME", TTL: 1, Data: seq}},
	}
	buildDNSPacketsErr(t, d, "domain name")
}

// TestDNSTXTLengthValidation 验证 TXT 单串 >255 报错、合法列表正常回读(A4)。
func TestDNSTXTLengthValidation(t *testing.T) {
	t.Run("too-long", func(t *testing.T) {
		d := &scenario.DNSFields{
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "TXT"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "TXT", TTL: 1, Data: scalarNode(strings.Repeat("a", 256))}},
		}
		buildDNSPacketsErr(t, d, "超 255")
	})
	t.Run("valid-list", func(t *testing.T) {
		// YAML 列表式 TXT:两条均 ≤255
		list := yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "v=spf1 include:_spf.example.com ~all"},
			{Kind: yaml.ScalarNode, Value: "second-string"},
		}}
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "TXT"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "TXT", TTL: 300, Data: list}},
		}
		got := buildDNSPackets(t, d)[0]
		if len(got.Answers) != 1 || len(got.Answers[0].TXTs) != 2 {
			t.Fatalf("TXT 串数 = %d,期望 2", len(got.Answers[0].TXTs))
		}
		if string(got.Answers[0].TXTs[1]) != "second-string" {
			t.Fatalf("第 2 条 TXT = %q", got.Answers[0].TXTs[1])
		}
	})
}

// TestDNSTrailingDotsRobust 验证双尾点不再产出双根终止符(A5)。
func TestDNSTrailingDotsRobust(t *testing.T) {
	d := &scenario.DNSFields{
		Questions: []scenario.DNSQuestionFields{{Name: "example.com..", Type: "A"}},
	}
	got := buildDNSPackets(t, d)[0]
	if string(got.Questions[0].Name) != "example.com" {
		t.Fatalf("双尾点归一化后 name = %q,期望 example.com", got.Questions[0].Name)
	}
}

// TestDNSUnknownEnumErrors 验证未知 type/class/opcode/rcode/qr 在 build 时报错,
// 而非静默降级为默认值。
func TestDNSUnknownEnumErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(d *scenario.DNSFields)
		wantSub string
	}{
		{"type", func(d *scenario.DNSFields) { d.Questions[0].Type = "SOA" }, "未知 type"},
		{"class", func(d *scenario.DNSFields) { d.Questions[0].Class = "NONE" }, "未知 class"},
		{"opcode", func(d *scenario.DNSFields) { d.Opcode = "notify" }, "未知 opcode"},
		{"rcode", func(d *scenario.DNSFields) { d.QR = "response"; d.RCode = "nx_domain" }, "未知 rcode"},
		{"qr", func(d *scenario.DNSFields) { d.QR = "resp" }, "未知 qr"},
		{"rr-type", func(d *scenario.DNSFields) {
			d.Answers = []scenario.DNSRRFields{{Name: "example.com", Type: "DS", TTL: 1, Data: scalarNode("0x00")}}
		}, "未知 type"},
		{"rr-class", func(d *scenario.DNSFields) {
			d.Answers = []scenario.DNSRRFields{{Name: "example.com", Type: "A", Class: "NONE", TTL: 1, Data: scalarNode("10.0.0.1")}}
		}, "未知 class"},
	}
	base := func() *scenario.DNSFields {
		return &scenario.DNSFields{
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A", Class: "IN"}},
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base()
			tc.mutate(d)
			buildDNSPacketsErr(t, d, tc.wantSub)
		})
	}
}

// TestDNSOmittedEnumDefaults 验证省略 type/class/opcode/rcode/qr 时走合理默认,
// 不报错、不降级歧义(回归)。
func TestDNSOmittedEnumDefaults(t *testing.T) {
	d := &scenario.DNSFields{
		// 全部枚举字段省略,仅给一个 question 的 name
		Questions: []scenario.DNSQuestionFields{{Name: "example.com"}},
	}
	got := buildDNSPackets(t, d)[0]
	if got.QR {
		t.Fatalf("省略 qr 应默认 query(false),实际 QR=true")
	}
	if got.OpCode != layers.DNSOpCodeQuery {
		t.Fatalf("省略 opcode 应默认 query,实际 %v", got.OpCode)
	}
	if got.ResponseCode != layers.DNSResponseCodeNoErr {
		t.Fatalf("省略 rcode 应默认 no_error,实际 %v", got.ResponseCode)
	}
	if got.Questions[0].Type != layers.DNSTypeA {
		t.Fatalf("省略 type 应默认 A,实际 %v", got.Questions[0].Type)
	}
	if got.Questions[0].Class != layers.DNSClassIN {
		t.Fatalf("省略 class 应默认 IN,实际 %v", got.Questions[0].Class)
	}
}
