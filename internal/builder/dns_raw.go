package builder

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// encodeDNSMessageRaw 手写一条完整 DNS 消息(RFC 1035 §4.1),用于 payload_hex / 未知
// type 等 gopacket 无法序列化的场景。与 gopacket 路径的语义对齐:
//   - 报头计数(QD/AN/NS/AR)由实际段长推导,恒与记录数一致(不构造计数错配;那属于 1.1)。
//   - 名字不做压缩指针(与 gopacket encodeName 一致),逐标签展开,利于确定性。
//   - 带 payload_hex 的 RR:RDATA = 原始字节,RDLENGTH = len(RDATA)。
//   - 不带 payload_hex 的 RR:按 type 结构化编码 RDATA;若是未知 type 又无 payload_hex,
//     无法得知 RDATA 内容,报错。
func encodeDNSMessageRaw(f *scenario.DNSFields, h dnsHeader) ([]byte, error) {
	// 预编码所有 question 与 RR,先算总长再一次性写,避免 PrependBytes 之外的动态扩容。
	questions, err := encodeDNSQuestionsRaw(f.Questions)
	if err != nil {
		return nil, fmt.Errorf("questions: %w", err)
	}
	type encodedRR struct {
		name  []byte
		typ   layers.DNSType
		class layers.DNSClass
		ttl   uint32
		rdata []byte
	}
	encodeSection := func(rrs []scenario.DNSRRFields) ([]encodedRR, error) {
		out := make([]encodedRR, 0, len(rrs))
		for i, rr := range rrs {
			n, err := encodeDNSNameBytes(rr.Name)
			if err != nil {
				return nil, fmt.Errorf("[%d] name: %w", i, err)
			}
			typ, err := dnsType(rr.Type)
			if err != nil {
				return nil, fmt.Errorf("[%d] type: %w", i, err)
			}
			class, err := dnsClass(rr.Class)
			if err != nil {
				return nil, fmt.Errorf("[%d] class: %w", i, err)
			}
			var rdata []byte
			if rr.PayloadHex != "" {
				rdata, err = scenario.ParsePayloadHex(rr.PayloadHex)
				if err != nil {
					return nil, fmt.Errorf("[%d] payload_hex: %w", i, err)
				}
			} else {
				rdata, err = encodeRData(typ, rr)
				if err != nil {
					return nil, fmt.Errorf("[%d]: %w", i, err)
				}
			}
			out = append(out, encodedRR{name: n, typ: typ, class: class, ttl: rr.TTL, rdata: rdata})
		}
		return out, nil
	}
	answers, err := encodeSection(f.Answers)
	if err != nil {
		return nil, fmt.Errorf("answers: %w", err)
	}
	authorities, err := encodeSection(f.Authorities)
	if err != nil {
		return nil, fmt.Errorf("authorities: %w", err)
	}
	additionals, err := encodeSection(f.Additionals)
	if err != nil {
		return nil, fmt.Errorf("additionals: %w", err)
	}

	// 总长 = 12(报头) + questions + 各 RR(name + 10 定长 + rdata)。
	total := 12
	for _, q := range questions {
		total += len(q.name) + 4
	}
	rrSize := func(r encodedRR) int { return len(r.name) + 10 + len(r.rdata) }
	for _, sec := range [][]encodedRR{answers, authorities, additionals} {
		for _, r := range sec {
			total += rrSize(r)
		}
	}

	buf := make([]byte, total)
	// 报头(RFC 1035 §4.1.1)。
	binary.BigEndian.PutUint16(buf[0:], h.id)
	buf[2] = byte(b2u8(h.qr)<<7 | uint8(h.opcode)<<3 | b2u8(h.aa)<<2 | b2u8(h.tc)<<1 | b2u8(h.rd))
	buf[3] = byte(b2u8(h.ra)<<7 | uint8(h.z)<<4 | uint8(h.rcode))
	binary.BigEndian.PutUint16(buf[4:], uint16(len(questions)))
	binary.BigEndian.PutUint16(buf[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(buf[8:], uint16(len(authorities)))
	binary.BigEndian.PutUint16(buf[10:], uint16(len(additionals)))

	off := 12
	for _, q := range questions {
		off += copy(buf[off:], q.name)
		binary.BigEndian.PutUint16(buf[off:], uint16(q.typ))
		binary.BigEndian.PutUint16(buf[off+2:], uint16(q.class))
		off += 4
	}
	writeRRs := func(sec []encodedRR) {
		for _, r := range sec {
			off += copy(buf[off:], r.name)
			binary.BigEndian.PutUint16(buf[off:], uint16(r.typ))
			binary.BigEndian.PutUint16(buf[off+2:], uint16(r.class))
			binary.BigEndian.PutUint32(buf[off+4:], r.ttl)
			binary.BigEndian.PutUint16(buf[off+8:], uint16(len(r.rdata))) // RDLENGTH = 实际 RDATA 长度
			off += 10
			off += copy(buf[off:], r.rdata)
		}
	}
	writeRRs(answers)
	writeRRs(authorities)
	writeRRs(additionals)
	if off != total {
		return nil, fmt.Errorf("dns raw 编码长度不匹配:已写 %d,预期 %d", off, total)
	}
	return buf, nil
}

// encodeDNSQuestionsRaw 编码所有 question(name + type + class)。
func encodeDNSQuestionsRaw(qs []scenario.DNSQuestionFields) ([]dnsRawQuestion, error) {
	out := make([]dnsRawQuestion, 0, len(qs))
	for i, q := range qs {
		name, err := encodeDNSNameBytes(q.Name)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		typ, err := dnsType(q.Type)
		if err != nil {
			return nil, fmt.Errorf("[%d] type: %w", i, err)
		}
		class, err := dnsClass(q.Class)
		if err != nil {
			return nil, fmt.Errorf("[%d] class: %w", i, err)
		}
		out = append(out, dnsRawQuestion{name: name, typ: typ, class: class})
	}
	return out, nil
}

type dnsRawQuestion struct {
	name  []byte
	typ   layers.DNSType
	class layers.DNSClass
}

// encodeDNSNameBytes 把点分域名(无尾点)编码为 DNS wire 格式:
// 逐标签「长度字节 + 标签内容」,末尾追加 0x00 根终止符(RFC 1035 §3.1 / §4.1.4)。
// 不生成压缩指针,与 gopacket encodeName 行为一致。合法性已由 validateDNSName 校验。
func encodeDNSNameBytes(s string) ([]byte, error) {
	// 复用 dnsName 的归一化 + 校验,确保与 gopacket 路径口径一致。
	norm, err := dnsName(s)
	if err != nil {
		return nil, err
	}
	if len(norm) == 0 {
		return []byte{0x00}, nil // 根域:单字节 0
	}
	// 长度上限:每个标签 +1 长度字节,再加 1 根终止符;validateDNSName 已保证 ≤255。
	out := make([]byte, 0, len(norm)+2)
	start := 0
	for i := 0; i <= len(norm); i++ {
		if i == len(norm) || norm[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, norm[start:i]...)
			start = i + 1
		}
	}
	out = append(out, 0x00)
	return out, nil
}

// encodeRData 按 type 结构化编码 RDATA(不带 payload_hex 的 RR)。复刻当前已支持的结构化
// 类型;未知 type 在此报错 —— 它们必须配 payload_hex 给出原始 RDATA。
func encodeRData(typ layers.DNSType, rr scenario.DNSRRFields) ([]byte, error) {
	switch typ {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		var s string
		if err := rr.Data.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s data 需要 IP 字符串: %w", typ, err)
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("非法 IP %q", s)
		}
		if typ == layers.DNSTypeA {
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf("A 记录需要 IPv4: %q", s)
			}
			return ip, nil
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("AAAA 记录需要 IPv6: %q", s)
		}
		return ip.To16(), nil
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		var s string
		if err := rr.Data.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s data 需要 domain name 字符串: %w", typ, err)
		}
		return encodeDNSNameBytes(s)
	case layers.DNSTypeMX:
		var mx struct {
			Preference uint16 `yaml:"preference"`
			Exchange   string `yaml:"exchange"`
		}
		if err := rr.Data.Decode(&mx); err != nil {
			return nil, fmt.Errorf("MX data 需要 {preference, exchange}: %w", err)
		}
		if mx.Exchange == "" {
			return nil, fmt.Errorf("MX data.exchange 不能为空")
		}
		name, err := encodeDNSNameBytes(mx.Exchange)
		if err != nil {
			return nil, fmt.Errorf("MX exchange: %w", err)
		}
		out := make([]byte, 2+len(name))
		binary.BigEndian.PutUint16(out, mx.Preference)
		copy(out[2:], name)
		return out, nil
	case layers.DNSTypeTXT:
		var list []string
		if err := rr.Data.Decode(&list); err != nil {
			var s string
			if err := rr.Data.Decode(&s); err != nil {
				return nil, fmt.Errorf("TXT data 需要字符串或字符串列表: %w", err)
			}
			list = []string{s}
		}
		out := make([]byte, 0)
		for _, s := range list {
			if len(s) > 255 {
				return nil, fmt.Errorf("TXT 串长度 %d 超 255(RFC 1035 §3.3.14)", len(s))
			}
			out = append(out, byte(len(s)))
			out = append(out, s...)
		}
		return out, nil
	case layers.DNSTypeSOA:
		// SOA RDATA(RFC 1035 §3.3.13):MNAME + RNAME(wire 域名,与 gopacket encodeName 一致)
		// + SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM(5×uint32 大端)。
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
			return nil, fmt.Errorf("SOA data 需要 {mname, rname, serial, refresh, retry, expire, minimum}: %w", err)
		}
		if soa.MName == "" {
			return nil, fmt.Errorf("SOA data.mname 不能为空")
		}
		if soa.RName == "" {
			return nil, fmt.Errorf("SOA data.rname 不能为空")
		}
		mname, err := encodeDNSNameBytes(soa.MName)
		if err != nil {
			return nil, fmt.Errorf("SOA mname: %w", err)
		}
		rname, err := encodeDNSNameBytes(soa.RName)
		if err != nil {
			return nil, fmt.Errorf("SOA rname: %w", err)
		}
		out := make([]byte, 0, len(mname)+len(rname)+20)
		out = append(out, mname...)
		out = append(out, rname...)
		var tail [20]byte
		binary.BigEndian.PutUint32(tail[0:], soa.Serial)
		binary.BigEndian.PutUint32(tail[4:], soa.Refresh)
		binary.BigEndian.PutUint32(tail[8:], soa.Retry)
		binary.BigEndian.PutUint32(tail[12:], soa.Expire)
		binary.BigEndian.PutUint32(tail[16:], soa.Minimum)
		out = append(out, tail[:]...)
		return out, nil
	case layers.DNSTypeSRV:
		// SRV RDATA(RFC 2782):Priority + Weight + Port(3×uint16 大端)+ Target(wire 域名)。
		// 空 target 报错(与 buildDNSRR 的 SRV 分支同口径);根 target 哨兵请用 payload_hex。
		var srv struct {
			Priority uint16 `yaml:"priority"`
			Weight   uint16 `yaml:"weight"`
			Port     uint16 `yaml:"port"`
			Target   string `yaml:"target"`
		}
		if err := rr.Data.Decode(&srv); err != nil {
			return nil, fmt.Errorf("SRV data 需要 {priority, weight, port, target}: %w", err)
		}
		if srv.Target == "" {
			return nil, fmt.Errorf("SRV data.target 不能为空(根 target \"服务不可用\" 哨兵请用 payload_hex)")
		}
		name, err := encodeDNSNameBytes(srv.Target)
		if err != nil {
			return nil, fmt.Errorf("SRV target: %w", err)
		}
		out := make([]byte, 6+len(name))
		binary.BigEndian.PutUint16(out[0:], srv.Priority)
		binary.BigEndian.PutUint16(out[2:], srv.Weight)
		binary.BigEndian.PutUint16(out[4:], srv.Port)
		copy(out[6:], name)
		return out, nil
	default:
		return nil, fmt.Errorf("type %s 未配 payload_hex 时无法编码 RDATA(未知/未支持 type 需用 payload_hex 给出原始 RDATA)", typ)
	}
}

// b2u8 把 bool 转成 0/1,用于报头标志位拼装。
func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
