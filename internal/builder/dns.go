package builder

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildDNS(f *scenario.DNSFields) (gopacket.SerializableLayer, error) {
	h, err := resolveDNSHeader(f)
	if err != nil {
		return nil, err
	}
	// 任一 RR 带 payload_hex → 整条消息走手写编码:gopacket 的 DNS layer 对未知 type
	// 直接报错、对已知 type 强制结构化编码并忽略 rr.Data,没有"原始 RDATA"通道,
	// 故存在 payload_hex 时无法借用 gopacket 序列化,只能在本层自己拼 DNS 消息字节。
	if anyDNSRRHasPayloadHex(f) {
		raw, err := encodeDNSMessageRaw(f, h)
		if err != nil {
			return nil, err
		}
		return &dnsRawLayer{data: raw}, nil
	}
	d := &layers.DNS{
		ID:           f.ID,
		QR:           h.qr,
		OpCode:       h.opcode,
		AA:           f.Authoritative,
		TC:           f.Truncated,
		RD:           f.RecursionDesired,
		RA:           f.RecursionAvailable,
		Z:            h.z,
		ResponseCode: h.rcode,
	}
	for i, q := range f.Questions {
		name, err := dnsName(q.Name)
		if err != nil {
			return nil, fmt.Errorf("questions[%d]: %w", i, err)
		}
		qtype, err := dnsType(q.Type)
		if err != nil {
			return nil, fmt.Errorf("questions[%d] type: %w", i, err)
		}
		qclass, err := dnsClass(q.Class)
		if err != nil {
			return nil, fmt.Errorf("questions[%d] class: %w", i, err)
		}
		d.Questions = append(d.Questions, layers.DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}
	if d.Answers, err = buildDNSRRs(f.Answers); err != nil {
		return nil, fmt.Errorf("answers: %w", err)
	}
	if d.Authorities, err = buildDNSRRs(f.Authorities); err != nil {
		return nil, fmt.Errorf("authorities: %w", err)
	}
	if d.Additionals, err = buildDNSRRs(f.Additionals); err != nil {
		return nil, fmt.Errorf("additionals: %w", err)
	}
	return d, nil
}

// dnsHeader 承载已解析的 DNS 报头字段,raw 与 gopacket 两条路径共用。
type dnsHeader struct {
	id             uint16
	qr             bool
	opcode         layers.DNSOpCode
	aa, tc, rd, ra bool
	z              uint8
	rcode          layers.DNSResponseCode
}

// resolveDNSHeader 解析 DNSFields 的报头标志位(AD/CD 编入 Z,见 RFC 4035 §2)。
func resolveDNSHeader(f *scenario.DNSFields) (dnsHeader, error) {
	// DNS.Z 占 byte[3] 的 bit6-4(RFC 1035 保留位)。RFC 4035 §2 将其重新定义为
	// AD(bit5)/CD(bit4),bit6 仍必须为 0。gopacket 用 Z 字段承载这两位。
	var z uint8
	if f.AuthenticatedData {
		z |= 0x02 // AD → byte[3] bit5
	}
	if f.CheckingDisabled {
		z |= 0x01 // CD → byte[3] bit4
	}
	qr, err := dnsQR(f.QR)
	if err != nil {
		return dnsHeader{}, fmt.Errorf("qr: %w", err)
	}
	opcode, err := dnsOpCode(f.Opcode)
	if err != nil {
		return dnsHeader{}, fmt.Errorf("opcode: %w", err)
	}
	rcode, err := dnsRCode(f.RCode)
	if err != nil {
		return dnsHeader{}, fmt.Errorf("rcode: %w", err)
	}
	return dnsHeader{
		id:     f.ID,
		qr:     qr,
		opcode: opcode,
		aa:     f.Authoritative,
		tc:     f.Truncated,
		rd:     f.RecursionDesired,
		ra:     f.RecursionAvailable,
		z:      z,
		rcode:  rcode,
	}, nil
}

// anyDNSRRHasPayloadHex 报告 answers/authorities/additionals 中是否有 RR 显式给了 payload_hex。
func anyDNSRRHasPayloadHex(f *scenario.DNSFields) bool {
	for _, sec := range [][]scenario.DNSRRFields{f.Answers, f.Authorities, f.Additionals} {
		for _, rr := range sec {
			if rr.PayloadHex != "" {
				return true
			}
		}
	}
	return false
}

// dnsRawLayer 持有已编码的完整 DNS 消息字节,实现 SerializableLayer 以便无侵入地
// 接入 SerializeLayers(UDP/TCP 层照常把它当 payload)。用于 payload_hex / 未知 type
// 这类 gopacket 无法表达的畸形场景。
type dnsRawLayer struct {
	data []byte
}

func (d *dnsRawLayer) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	buf, err := b.PrependBytes(len(d.data))
	if err != nil {
		return err
	}
	copy(buf, d.data)
	return nil
}

func (d *dnsRawLayer) LayerType() gopacket.LayerType { return layers.LayerTypeDNS }

func buildDNSRRs(in []scenario.DNSRRFields) ([]layers.DNSResourceRecord, error) {
	out := make([]layers.DNSResourceRecord, 0, len(in))
	for i, rr := range in {
		built, err := buildDNSRR(rr)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, built)
	}
	return out, nil
}

func buildDNSRR(rr scenario.DNSRRFields) (layers.DNSResourceRecord, error) {
	typ, err := dnsType(rr.Type)
	if err != nil {
		return layers.DNSResourceRecord{}, fmt.Errorf("type: %w", err)
	}
	name, err := dnsName(rr.Name)
	if err != nil {
		return layers.DNSResourceRecord{}, fmt.Errorf("name: %w", err)
	}
	class, err := dnsClass(rr.Class)
	if err != nil {
		return layers.DNSResourceRecord{}, fmt.Errorf("class: %w", err)
	}
	out := layers.DNSResourceRecord{
		Name:  name,
		Type:  typ,
		Class: class,
		TTL:   rr.TTL,
	}
	switch typ {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		var s string
		if err := rr.Data.Decode(&s); err != nil {
			return out, fmt.Errorf("%s data 需要 IP 字符串: %w", typ, err)
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return out, fmt.Errorf("非法 IP %q", s)
		}
		if typ == layers.DNSTypeA {
			ip = ip.To4()
			if ip == nil {
				return out, fmt.Errorf("A 记录需要 IPv4: %q", s)
			}
		}
		out.IP = ip
	case layers.DNSTypeCNAME:
		n, err := dnsNameString(rr)
		if err != nil {
			return out, fmt.Errorf("CNAME data: %w", err)
		}
		out.CNAME = n
	case layers.DNSTypeNS:
		n, err := dnsNameString(rr)
		if err != nil {
			return out, fmt.Errorf("NS data: %w", err)
		}
		out.NS = n
	case layers.DNSTypePTR:
		n, err := dnsNameString(rr)
		if err != nil {
			return out, fmt.Errorf("PTR data: %w", err)
		}
		out.PTR = n
	case layers.DNSTypeMX:
		var mx struct {
			Preference uint16 `yaml:"preference"`
			Exchange   string `yaml:"exchange"`
		}
		if err := rr.Data.Decode(&mx); err != nil {
			return out, fmt.Errorf("MX data 需要 {preference, exchange}: %w", err)
		}
		if mx.Exchange == "" {
			return out, fmt.Errorf("MX data.exchange 不能为空")
		}
		name, err := dnsName(mx.Exchange)
		if err != nil {
			return out, fmt.Errorf("MX exchange: %w", err)
		}
		out.MX = layers.DNSMX{Preference: mx.Preference, Name: name}
	case layers.DNSTypeTXT:
		var list []string
		if err := rr.Data.Decode(&list); err != nil {
			var s string
			if err := rr.Data.Decode(&s); err != nil {
				return out, fmt.Errorf("TXT data 需要字符串或字符串列表: %w", err)
			}
			list = []string{s}
		}
		for _, s := range list {
			if len(s) > 255 {
				return out, fmt.Errorf("TXT 串长度 %d 超 255(RFC 1035 §3.3.14)", len(s))
			}
			out.TXTs = append(out.TXTs, []byte(s))
		}
	case layers.DNSTypeSOA:
		// SOA RDATA(RFC 1035 §3.3.13):MNAME(主权威服务器)+ RNAME(负责人邮箱,域名编码)
		// + SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM(5×uint32,秒)。MName/RName 走 dnsName
		// 归一化+校验,与 CNAME/NS/PTR 同口径;畸形 SOA 由 payload_hex 兜底。
		var soa struct {
			MName   string `yaml:"mname"`
			RName   string `yaml:"rname"`
			Serial  uint32 `yaml:"serial"`
			Refresh uint32 `yaml:"refresh"`
			Retry   uint32 `yaml:"retry"`
			Expire  uint32 `yaml:"expire"`
			Minimum uint32 `yaml:"minimum"`
		}
		if err := rr.Data.Decode(&soa); err != nil {
			return out, fmt.Errorf("SOA data 需要 {mname, rname, serial, refresh, retry, expire, minimum}: %w", err)
		}
		if soa.MName == "" {
			return out, fmt.Errorf("SOA data.mname 不能为空")
		}
		if soa.RName == "" {
			return out, fmt.Errorf("SOA data.rname 不能为空")
		}
		mname, err := dnsName(soa.MName)
		if err != nil {
			return out, fmt.Errorf("SOA mname: %w", err)
		}
		rname, err := dnsName(soa.RName)
		if err != nil {
			return out, fmt.Errorf("SOA rname: %w", err)
		}
		out.SOA = layers.DNSSOA{
			MName:   mname,
			RName:   rname,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minimum: soa.Minimum,
		}
	case layers.DNSTypeSRV:
		// SRV RDATA(RFC 2782):Priority(uint16)+ Weight(uint16)+ Port(uint16)+ Target(域名)。
		// Target 走 dnsName 归一化+校验;空 target 报错(与 MX 的 "exchange 不能为空" 同口径,
		// 避免省略 target 静默退化为根)。RFC 2782 §1 的根 target("服务不可用"哨兵)请用
		// payload_hex 给原始 RDATA:gopacket 对根名 RR 的 RDLENGTH 会多算 1 字节,无法正确编码。
		var srv struct {
			Priority uint16 `yaml:"priority"`
			Weight   uint16 `yaml:"weight"`
			Port     uint16 `yaml:"port"`
			Target   string `yaml:"target"`
		}
		if err := rr.Data.Decode(&srv); err != nil {
			return out, fmt.Errorf("SRV data 需要 {priority, weight, port, target}: %w", err)
		}
		if srv.Target == "" {
			return out, fmt.Errorf("SRV data.target 不能为空(根 target \"服务不可用\" 哨兵请用 payload_hex)")
		}
		name, err := dnsName(srv.Target)
		if err != nil {
			return out, fmt.Errorf("SRV target: %w", err)
		}
		out.SRV = layers.DNSSRV{Priority: srv.Priority, Weight: srv.Weight, Port: srv.Port, Name: name}
	default:
		return out, fmt.Errorf("暂不支持 DNS RR 类型 %q", rr.Type)
	}
	return out, nil
}

// validateDNSName / dnsType / dnsClass / dnsOpCode / dnsRCode / dnsQR /
// parseDNSRRNumber 等字符串↔枚举映射与校验见 dns_enum.go(构包与映射分离)。

// dnsNameString 从 RR data 读出域名并编码,用于 CNAME/NS/PTR。
// data 非字符串时返回错误,而非静默退化为根域。
func dnsNameString(rr scenario.DNSRRFields) ([]byte, error) {
	var s string
	if err := rr.Data.Decode(&s); err != nil {
		return nil, fmt.Errorf("需要 domain name 字符串: %w", err)
	}
	return dnsName(s)
}

// dnsName 把点分域名归一化为 gopacket encodeName 所需的"无尾点"形式。
// encodeName 自己补 root 终止符且不做长度校验,故此处在归一化后校验
// 单标签 ≤63、整名编码后 ≤255(RFC 1035 §3.1),避免静默产出非法名字。
func dnsName(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ".") // 去掉所有尾点,避免双尾点产出双根终止符
	if err := validateDNSName(s); err != nil {
		return nil, err
	}
	return []byte(s), nil
}
