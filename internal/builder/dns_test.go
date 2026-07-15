package builder_test

import (
	"bytes"
	"strconv"
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

// soaDataNode 构造 SOA data 的 mapping 节点(有序键),镜像 YAML map 输入。
// 数值标量显式标 Tag=!!int,确保 Decode 进 uint32;域名字符串由 yaml 推断为 !!str。
func soaDataNode(mname, rname string, serial, refresh, retry, expire, minimum uint32) yaml.Node {
	pairs := []struct {
		k string
		v string
	}{
		{"mname", mname},
		{"rname", rname},
		{"serial", strconv.FormatUint(uint64(serial), 10)},
		{"refresh", strconv.FormatUint(uint64(refresh), 10)},
		{"retry", strconv.FormatUint(uint64(retry), 10)},
		{"expire", strconv.FormatUint(uint64(expire), 10)},
		{"minimum", strconv.FormatUint(uint64(minimum), 10)},
	}
	n := yaml.Node{Kind: yaml.MappingNode}
	for _, p := range pairs {
		tag := "!!str"
		if p.k != "mname" && p.k != "rname" {
			tag = "!!int"
		}
		n.Content = append(n.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: p.k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: p.v},
		)
	}
	return n
}

// srvDataNode 构造 SRV data 的 mapping 节点(有序键),镜像 YAML map 输入。
// 数值标量显式标 Tag=!!int,确保 Decode 进 uint16;target 字符串由 yaml 推断为 !!str。
func srvDataNode(priority, weight, port uint16, target string) yaml.Node {
	pairs := []struct {
		k string
		v string
	}{
		{"priority", strconv.FormatUint(uint64(priority), 10)},
		{"weight", strconv.FormatUint(uint64(weight), 10)},
		{"port", strconv.FormatUint(uint64(port), 10)},
		{"target", target},
	}
	n := yaml.Node{Kind: yaml.MappingNode}
	for _, p := range pairs {
		tag := "!!str"
		if p.k != "target" {
			tag = "!!int"
		}
		n.Content = append(n.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: p.k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: p.v},
		)
	}
	return n
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
		{"type", func(d *scenario.DNSFields) { d.Questions[0].Type = "RRSIG" }, "未知 type"},
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

// TestDNSSOA 验证 SOA 记录经 gopacket 路径序列化后,7 个 RDATA 字段(RFC 1035 §3.3.13)
// 回读一致:MName/RName(注意回读无尾点)+ SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM。
func TestDNSSOA(t *testing.T) {
	d := &scenario.DNSFields{
		ID:                 0x123b,
		QR:                 "response",
		Authoritative:      true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		RCode:              "no_error",
		Questions:          []scenario.DNSQuestionFields{{Name: "example.com.", Type: "SOA", Class: "IN"}},
		Answers: []scenario.DNSRRFields{{
			Name: "example.com.", Type: "SOA", Class: "IN", TTL: 300,
			Data: soaDataNode("ns1.example.com.", "hostmaster.example.com.", 2024010101, 7200, 3600, 1209600, 3600),
		}},
	}
	got := buildDNSPackets(t, d)[0]
	if got.Answers[0].Type != layers.DNSTypeSOA {
		t.Fatalf("type = %v,期望 SOA", got.Answers[0].Type)
	}
	soa := got.Answers[0].SOA
	if string(soa.MName) != "ns1.example.com" || string(soa.RName) != "hostmaster.example.com" {
		t.Fatalf("SOA MName/RName = %q/%q,期望 ns1.example.com/hostmaster.example.com", soa.MName, soa.RName)
	}
	if soa.Serial != 2024010101 || soa.Refresh != 7200 || soa.Retry != 3600 || soa.Expire != 1209600 || soa.Minimum != 3600 {
		t.Fatalf("SOA 数值字段 = serial=%d refresh=%d retry=%d expire=%d minimum=%d",
			soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
	}
	if got.Answers[0].DataLength == 0 {
		t.Fatalf("SOA RDLENGTH = 0,期望非零")
	}
}

// TestDNSSOAValidation 验证 SOA 缺 MName/RName 在 build 时报错,而非静默退化为根域
// 或产出无意义记录。畸形 SOA 应走 payload_hex 兜底,而非结构化路径。
func TestDNSSOAValidation(t *testing.T) {
	full := func() yaml.Node {
		return soaDataNode("ns1.example.com.", "hostmaster.example.com.", 1, 1, 1, 1, 1)
	}
	t.Run("missing-mname", func(t *testing.T) {
		data := soaDataNode("", "hostmaster.example.com.", 1, 1, 1, 1, 1)
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "SOA"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "SOA", TTL: 1, Data: data}},
		}
		buildDNSPacketsErr(t, d, "mname 不能为空")
	})
	t.Run("missing-rname", func(t *testing.T) {
		data := soaDataNode("ns1.example.com.", "", 1, 1, 1, 1, 1)
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "SOA"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "SOA", TTL: 1, Data: data}},
		}
		buildDNSPacketsErr(t, d, "rname 不能为空")
	})
	t.Run("missing-both", func(t *testing.T) {
		data := soaDataNode("", "", 1, 1, 1, 1, 1)
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "SOA"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "SOA", TTL: 1, Data: data}},
		}
		buildDNSPacketsErr(t, d, "mname 不能为空")
	})
	// 防御:full 数据正常通过,避免上面校验误伤合法输入。
	t.Run("full-ok", func(t *testing.T) {
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "SOA"}},
			Answers:   []scenario.DNSRRFields{{Name: "example.com", Type: "SOA", TTL: 1, Data: full()}},
		}
		got := buildDNSPackets(t, d)[0]
		if got.Answers[0].Type != layers.DNSTypeSOA {
			t.Fatalf("type = %v,期望 SOA", got.Answers[0].Type)
		}
	})
}

// TestDNSSRV 验证 SRV 记录经 gopacket 路径序列化后,4 个 RDATA 字段(RFC 2782)
// 回读一致:Priority/Weight/Port + Target(回读无尾点,与 MX/SOA 同口径)。
func TestDNSSRV(t *testing.T) {
	d := &scenario.DNSFields{
		ID:                 0x123c,
		QR:                 "response",
		Authoritative:      true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		RCode:              "no_error",
		Questions:          []scenario.DNSQuestionFields{{Name: "_sip._tcp.example.com.", Type: "SRV", Class: "IN"}},
		Answers: []scenario.DNSRRFields{{
			Name: "_sip._tcp.example.com.", Type: "SRV", Class: "IN", TTL: 300,
			Data: srvDataNode(10, 20, 5060, "sipserver.example.com."),
		}},
	}
	got := buildDNSPackets(t, d)[0]
	if got.Answers[0].Type != layers.DNSTypeSRV {
		t.Fatalf("type = %v,期望 SRV", got.Answers[0].Type)
	}
	srv := got.Answers[0].SRV
	if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 5060 {
		t.Fatalf("SRV Priority/Weight/Port = %d/%d/%d,期望 10/20/5060", srv.Priority, srv.Weight, srv.Port)
	}
	if string(srv.Name) != "sipserver.example.com" {
		t.Fatalf("SRV Target = %q,期望 sipserver.example.com", srv.Name)
	}
	if got.Answers[0].DataLength == 0 {
		t.Fatalf("SRV RDLENGTH = 0,期望非零")
	}
}

// TestDNSSRVValidation 验证 SRV 校验:data 非 map 报错;空 target 报错(与 MX 的
// "exchange 不能为空" 同口径,避免省略 target 静默退化为根)。根 target("服务不可用"
// 哨兵)用 payload_hex 构造,见 TestDNSRawSRVRootTarget。
func TestDNSSRVValidation(t *testing.T) {
	t.Run("non-map-data", func(t *testing.T) {
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "_sip._tcp.example.com", Type: "SRV"}},
			Answers:   []scenario.DNSRRFields{{Name: "_sip._tcp.example.com", Type: "SRV", TTL: 1, Data: scalarNode("not-a-map")}},
		}
		buildDNSPacketsErr(t, d, "SRV data")
	})
	t.Run("empty-target", func(t *testing.T) {
		// target 空/省略 → 报错,而非静默退化为根("服务不可用"哨兵)。
		d := &scenario.DNSFields{
			QR:        "response",
			Questions: []scenario.DNSQuestionFields{{Name: "_sip._tcp.example.com", Type: "SRV"}},
			Answers: []scenario.DNSRRFields{{
				Name: "_sip._tcp.example.com", Type: "SRV", Class: "IN", TTL: 300,
				Data: srvDataNode(0, 0, 0, ""),
			}},
		}
		buildDNSPacketsErr(t, d, "target 不能为空")
	})
}
