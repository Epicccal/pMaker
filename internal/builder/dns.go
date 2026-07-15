package builder

import (
	"fmt"
	"net"
	"strconv"
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
	default:
		return out, fmt.Errorf("暂不支持 DNS RR 类型 %q", rr.Type)
	}
	return out, nil
}

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

// validateDNSName 校验域名单标签长度(≤63)与整名编码长度(≤255)。
// 入参 s 已去除尾点;空串表示根域,合法。
func validateDNSName(s string) error {
	if s == "" {
		return nil // 根域
	}
	total := 1 // 根终止符
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			labelLen := i - start
			if labelLen == 0 {
				return fmt.Errorf("域名含空标签: %q", s)
			}
			if labelLen > 63 {
				return fmt.Errorf("域名单标签长度 %d 超 63(RFC 1035 §3.1): %q", labelLen, s[start:i])
			}
			total += labelLen + 1 // 长度字节 + 标签内容
			start = i + 1
		}
	}
	if total > 255 {
		return fmt.Errorf("域名编码后长度 %d 超 255(RFC 1035 §3.1): %q", total, s)
	}
	return nil
}

// dnsType 解析 RR/QType 字符串。接受三种写法:
//   - 省略 → 默认 A
//   - 已知名字(A/AAAA/CNAME/NS/PTR/MX/TXT)→ 对应 DNSType
//   - 数字("99" / "0x0063" / "0063")→ 任意 type,用于未知 RR / 私有码模糊测试
//
// 数字 type 通常需配合 payload_hex 提供原始 RDATA(见 encodeDNSMessage)。
func dnsType(s string) (layers.DNSType, error) {
	if s == "" {
		return layers.DNSTypeA, nil // 省略 → 默认 A
	}
	switch strings.ToUpper(s) {
	case "A":
		return layers.DNSTypeA, nil
	case "AAAA":
		return layers.DNSTypeAAAA, nil
	case "CNAME":
		return layers.DNSTypeCNAME, nil
	case "NS":
		return layers.DNSTypeNS, nil
	case "PTR":
		return layers.DNSTypePTR, nil
	case "MX":
		return layers.DNSTypeMX, nil
	case "TXT":
		return layers.DNSTypeTXT, nil
	}
	// 非已知名字:尝试按数字解析,允许造未知/私有 type。
	v, err := parseDNSRRNumber(s, "type")
	if err != nil {
		return 0, err
	}
	return layers.DNSType(v), nil
}

// parseDNSRRNumber 把字符串当 uint16 数字解析,支持十进制与 0x 十六进制。
// 用于 type/class 的数字写法(未知/私有码)。what 用于错误信息。
func parseDNSRRNumber(s, what string) (uint16, error) {
	t := strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		t = t[2:]
		base = 16
	}
	n, err := strconv.ParseUint(t, base, 16)
	if err != nil {
		return 0, fmt.Errorf("未知 %s %q(支持名字或数字如 99 / 0x0063)", what, s)
	}
	if n > 0xffff {
		return 0, fmt.Errorf("%s %q 超出 uint16 范围", what, s)
	}
	return uint16(n), nil
}

func dnsClass(s string) (layers.DNSClass, error) {
	if s == "" {
		return layers.DNSClassIN, nil // 省略 → 默认 IN
	}
	switch strings.ToUpper(s) {
	case "IN":
		return layers.DNSClassIN, nil
	case "CS":
		return layers.DNSClassCS, nil
	case "CH":
		return layers.DNSClassCH, nil
	case "HS":
		return layers.DNSClassHS, nil
	default:
		return 0, fmt.Errorf("未知 class %q(支持 IN/CS/CH/HS)", s)
	}
}

func dnsOpCode(s string) (layers.DNSOpCode, error) {
	if s == "" {
		return layers.DNSOpCodeQuery, nil // 省略 → 默认 query
	}
	switch strings.ToLower(s) {
	case "query":
		return layers.DNSOpCodeQuery, nil
	case "iquery":
		return layers.DNSOpCodeIQuery, nil
	case "status":
		return layers.DNSOpCodeStatus, nil
	default:
		return 0, fmt.Errorf("未知 opcode %q(支持 query/iquery/status)", s)
	}
}

func dnsRCode(s string) (layers.DNSResponseCode, error) {
	if s == "" {
		return layers.DNSResponseCodeNoErr, nil // 省略 → 默认 no_error
	}
	switch strings.ToLower(s) {
	case "no_error":
		return layers.DNSResponseCodeNoErr, nil
	case "format_error":
		return layers.DNSResponseCodeFormErr, nil
	case "server_failure":
		return layers.DNSResponseCodeServFail, nil
	case "name_error":
		return layers.DNSResponseCodeNXDomain, nil
	case "not_implemented":
		return layers.DNSResponseCodeNotImp, nil
	case "refused":
		return layers.DNSResponseCodeRefused, nil
	default:
		return 0, fmt.Errorf("未知 rcode %q(支持 no_error/format_error/server_failure/name_error/not_implemented/refused)", s)
	}
}

// dnsQR 把 qr 字符串解析成响应标志:省略或 "query" → false(查询),"response" → true,
// 其余报错,避免把拼写错误(如 "resp")静默当成查询。
func dnsQR(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "", "query":
		return false, nil
	case "response":
		return true, nil
	default:
		return false, fmt.Errorf("未知 qr %q(支持 query/response)", s)
	}
}
