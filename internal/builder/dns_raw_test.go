package builder_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// dnsRRPayloadHex 构造一个带 payload_hex 的 DNSRRFields。
func dnsRRPayloadHex(name, typ, class string, ttl uint32, ph string) scenario.DNSRRFields {
	return scenario.DNSRRFields{Name: name, Type: typ, Class: class, TTL: ttl, PayloadHex: ph}
}

// readDNSOnce 跑 build→write→回读,返回唯一 DNS 层(供 raw 路径测试复用)。
func readDNSOnce(t *testing.T, d *scenario.DNSFields) *layers.DNS {
	t.Helper()
	return buildDNSPackets(t, d)[0]
}

// rawBytesEqual 比较回读出的 RDATA 与期望原始字节。
func rawBytesEqual(t *testing.T, rr layers.DNSResourceRecord, want []byte, hint string) {
	t.Helper()
	if !bytes.Equal(rr.Data, want) {
		t.Fatalf("%s: RDATA = %x,期望 %x", hint, rr.Data, want)
	}
}

// TestDNSRawUnknownType 验证未知 type(数字)+ payload_hex 落原始 RDATA(A2 核心)。
func TestDNSRawUnknownType(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		wantTyp layers.DNSType
	}{
		{"decimal", "99", 99},
		{"hex", "0x0063", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &scenario.DNSFields{
				QR:        "response",
				Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "TXT"}},
				Answers:   []scenario.DNSRRFields{dnsRRPayloadHex("example.com", tc.typ, "IN", 300, "0xdeadbeef")},
			}
			got := readDNSOnce(t, d)
			if got.Answers[0].Type != tc.wantTyp {
				t.Fatalf("type = %d,期望 %d", got.Answers[0].Type, tc.wantTyp)
			}
			rawBytesEqual(t, got.Answers[0], []byte{0xde, 0xad, 0xbe, 0xef}, "未知 type RDATA")
			if got.Answers[0].DataLength != 4 {
				t.Fatalf("RDLENGTH = %d,期望 4", got.Answers[0].DataLength)
			}
		})
	}
}

// TestDNSRawKnownTypeMalformedRDATA 验证已知 type(A)+ 非法长度 RDATA 原样落字节。
func TestDNSRawKnownTypeMalformedRDATA(t *testing.T) {
	d := &scenario.DNSFields{
		QR:        "response",
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
		// A 记录合法 RDATA 应为 4 字节,此处故意给 3 字节测设备如何处理。
		Answers: []scenario.DNSRRFields{dnsRRPayloadHex("example.com", "A", "IN", 300, "0x010203")},
	}
	got := readDNSOnce(t, d)
	if got.Answers[0].Type != layers.DNSTypeA {
		t.Fatalf("type = %v,期望 A", got.Answers[0].Type)
	}
	rawBytesEqual(t, got.Answers[0], []byte{0x01, 0x02, 0x03}, "畸形 A RDATA")
	if got.Answers[0].DataLength != 3 {
		t.Fatalf("RDLENGTH = %d,期望 3(应等于实际 RDATA,不被修正为 4)", got.Answers[0].DataLength)
	}
}

// TestDNSRawMixedRRs 验证同一条消息混合:payload_hex RR(未知 type)+ 结构化 A RR。
// 后者证明 raw 编码器复刻的 A 编码与 gopacket 一致。
func TestDNSRawMixedRRs(t *testing.T) {
	d := &scenario.DNSFields{
		QR:        "response",
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
		Answers: []scenario.DNSRRFields{
			dnsRRPayloadHex("priv.example.com", "99", "IN", 60, "0xcafe"),
			{Name: "example.com", Type: "A", Class: "IN", TTL: 300, Data: scalarNode("93.184.216.34")},
		},
	}
	got := readDNSOnce(t, d)
	if len(got.Answers) != 2 {
		t.Fatalf("answers 数 = %d,期望 2", len(got.Answers))
	}
	// 第 1 条:未知 type + raw RDATA。
	if got.Answers[0].Type != 99 {
		t.Fatalf("answers[0] type = %d,期望 99", got.Answers[0].Type)
	}
	rawBytesEqual(t, got.Answers[0], []byte{0xca, 0xfe}, "混合 answers[0]")
	// 第 2 条:结构化 A,回读 IP 应正确。
	if got.Answers[1].Type != layers.DNSTypeA {
		t.Fatalf("answers[1] type = %v,期望 A", got.Answers[1].Type)
	}
	if !got.Answers[1].IP.Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("answers[1] IP = %v,期望 93.184.216.34", got.Answers[1].IP)
	}
}

// TestDNSRawStructuredRData 验证 raw 路径对结构化类型(CNAME/MX/TXT)的编码正确。
// 用一个 payload_hex RR 把整条消息推入 raw 路径,再校结构化 RR 回读值。
func TestDNSRawStructuredRData(t *testing.T) {
	d := &scenario.DNSFields{
		QR:        "response",
		Questions: []scenario.DNSQuestionFields{{Name: "www.example.com", Type: "CNAME"}},
		Answers: []scenario.DNSRRFields{
			{Name: "www.example.com", Type: "CNAME", Class: "IN", TTL: 300, Data: scalarNode("example.com")},
			dnsRRPayloadHex("x.example.com", "99", "IN", 1, "0x00"), // 触发 raw 路径
		},
	}
	got := readDNSOnce(t, d)
	if string(got.Answers[0].CNAME) != "example.com" {
		t.Fatalf("CNAME = %q,期望 example.com", got.Answers[0].CNAME)
	}
}

// TestDNSPayloadHexDataMutex 验证 payload_hex 与 data 互斥(validate 报错)。
func TestDNSPayloadHexDataMutex(t *testing.T) {
	d := &scenario.DNSFields{
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
		Answers: []scenario.DNSRRFields{
			{Name: "example.com", Type: "A", Class: "IN", TTL: 300, Data: scalarNode("1.2.3.4"), PayloadHex: "0xdeadbeef"},
		},
	}
	s := dnsScenario(d)
	if err := scenario.Validate(s); err == nil {
		t.Fatal("期望 validate 报互斥错误,实际通过")
	}
}

// TestDNSRawHeaderFlags 验证 raw 路径报头标志位(QR/AA/RD/RA/AD/CD/RCODE)与 gopacket 一致。
func TestDNSRawHeaderFlags(t *testing.T) {
	d := &scenario.DNSFields{
		ID:                 0xabcd,
		QR:                 "response",
		Authoritative:      true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		AuthenticatedData:  true,
		CheckingDisabled:   true,
		RCode:              "name_error",
		Questions:          []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
		Answers:            []scenario.DNSRRFields{dnsRRPayloadHex("example.com", "99", "IN", 1, "0x00")},
	}
	got := readDNSOnce(t, d)
	if got.ID != 0xabcd {
		t.Fatalf("ID = %#x,期望 abcd", got.ID)
	}
	if !got.QR || !got.AA || !got.RD || !got.RA {
		t.Fatalf("标志位 QR=%v AA=%v RD=%v RA=%v,期望全 true", got.QR, got.AA, got.RD, got.RA)
	}
	if got.ResponseCode != layers.DNSResponseCodeNXDomain {
		t.Fatalf("RCODE = %v,期望 NXDomain", got.ResponseCode)
	}
	// AD/CD 编入 Z(bits6-4):AD=0x20, CD=0x10 → Z 段 0x30。
	if got.Z != 0x03 {
		t.Fatalf("Z = %#x,期望 0x03(AD+CD)", got.Z)
	}
	b3 := got.Contents[3]
	if b3&0x30 != 0x30 {
		t.Fatalf("byte[3] AD/CD 段 = %#x,期望 0x30", b3&0x30)
	}
}

// TestDNSRawSOA 验证 raw 路径对结构化 SOA 的编码与 gopacket 一致:用一条 payload_hex RR
// 把整条消息推入 raw 路径,再校 SOA 回读值。证明 encodeRData 复刻的 SOA wire
// (MName + RName + 5×uint32)能被 gopacket 正确解析。
func TestDNSRawSOA(t *testing.T) {
	d := &scenario.DNSFields{
		QR:        "response",
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "SOA"}},
		Answers: []scenario.DNSRRFields{
			{
				Name: "example.com", Type: "SOA", Class: "IN", TTL: 3600,
				Data: soaDataNode("ns1.example.com.", "hostmaster.example.com.", 2024010101, 7200, 3600, 1209600, 3600),
			},
			dnsRRPayloadHex("x.example.com", "99", "IN", 1, "0x00"), // 触发 raw 路径
		},
	}
	got := readDNSOnce(t, d)
	if len(got.Answers) != 2 {
		t.Fatalf("answers 数 = %d,期望 2", len(got.Answers))
	}
	if got.Answers[0].Type != layers.DNSTypeSOA {
		t.Fatalf("answers[0] type = %v,期望 SOA", got.Answers[0].Type)
	}
	soa := got.Answers[0].SOA
	if string(soa.MName) != "ns1.example.com" || string(soa.RName) != "hostmaster.example.com" {
		t.Fatalf("raw 路径 SOA MName/RName = %q/%q", soa.MName, soa.RName)
	}
	if soa.Serial != 2024010101 || soa.Refresh != 7200 || soa.Retry != 3600 || soa.Expire != 1209600 || soa.Minimum != 3600 {
		t.Fatalf("raw 路径 SOA 数值字段 = serial=%d refresh=%d retry=%d expire=%d minimum=%d",
			soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
	}
}
