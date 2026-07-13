package builder

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildDNS(f *scenario.DNSFields) (*layers.DNS, error) {
	// DNS.Z 占 byte[3] 的 bit6-4(RFC 1035 保留位)。RFC 4035 §2 将其重新定义为
	// AD(bit5)/CD(bit4),bit6 仍必须为 0。gopacket 用 Z 字段承载这两位。
	var z uint8
	if f.AuthenticatedData {
		z |= 0x02 // AD → byte[3] bit5
	}
	if f.CheckingDisabled {
		z |= 0x01 // CD → byte[3] bit4
	}
	d := &layers.DNS{
		ID:           f.ID,
		QR:           strings.EqualFold(f.QR, "response"),
		OpCode:       dnsOpCode(f.Opcode),
		AA:           f.Authoritative,
		TC:           f.Truncated,
		RD:           f.RecursionDesired,
		RA:           f.RecursionAvailable,
		Z:            z,
		ResponseCode: dnsRCode(f.RCode),
	}
	for _, q := range f.Questions {
		name, err := dnsName(q.Name)
		if err != nil {
			return nil, fmt.Errorf("questions: %w", err)
		}
		d.Questions = append(d.Questions, layers.DNSQuestion{
			Name:  name,
			Type:  dnsType(q.Type),
			Class: dnsClass(q.Class),
		})
	}
	var err error
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
	typ := dnsType(rr.Type)
	name, err := dnsName(rr.Name)
	if err != nil {
		return layers.DNSResourceRecord{}, fmt.Errorf("name: %w", err)
	}
	out := layers.DNSResourceRecord{
		Name:  name,
		Type:  typ,
		Class: dnsClass(rr.Class),
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

func dnsType(s string) layers.DNSType {
	switch strings.ToUpper(orDefault(s, "A")) {
	case "A":
		return layers.DNSTypeA
	case "AAAA":
		return layers.DNSTypeAAAA
	case "CNAME":
		return layers.DNSTypeCNAME
	case "NS":
		return layers.DNSTypeNS
	case "PTR":
		return layers.DNSTypePTR
	case "MX":
		return layers.DNSTypeMX
	case "TXT":
		return layers.DNSTypeTXT
	default:
		return 0
	}
}

func dnsClass(s string) layers.DNSClass {
	switch strings.ToUpper(orDefault(s, "IN")) {
	case "IN":
		return layers.DNSClassIN
	case "CS":
		return layers.DNSClassCS
	case "CH":
		return layers.DNSClassCH
	case "HS":
		return layers.DNSClassHS
	default:
		return layers.DNSClassIN
	}
}

func dnsOpCode(s string) layers.DNSOpCode {
	switch strings.ToLower(orDefault(s, "query")) {
	case "iquery":
		return layers.DNSOpCodeIQuery
	case "status":
		return layers.DNSOpCodeStatus
	default:
		return layers.DNSOpCodeQuery
	}
}

func dnsRCode(s string) layers.DNSResponseCode {
	switch strings.ToLower(orDefault(s, "no_error")) {
	case "format_error":
		return layers.DNSResponseCodeFormErr
	case "server_failure":
		return layers.DNSResponseCodeServFail
	case "name_error":
		return layers.DNSResponseCodeNXDomain
	case "not_implemented":
		return layers.DNSResponseCodeNotImp
	case "refused":
		return layers.DNSResponseCodeRefused
	default:
		return layers.DNSResponseCodeNoErr
	}
}
