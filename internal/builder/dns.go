package builder

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildDNS(f *scenario.DNSFields) (*layers.DNS, error) {
	d := &layers.DNS{
		ID:           f.ID,
		QR:           strings.EqualFold(f.QR, "response"),
		OpCode:       dnsOpCode(f.Opcode),
		AA:           f.Authoritative,
		TC:           f.Truncated,
		RD:           f.RecursionDesired,
		RA:           f.RecursionAvailable,
		ResponseCode: dnsRCode(f.RCode),
	}
	// gopacket 的 DNS.Z 承载 AD/CD 位所在的保留字段;MVP 先不编码 AD/CD。
	if f.AuthenticatedData || f.CheckingDisabled {
		slog.Warn("最小版暂不编码 DNS authenticated_data/checking_disabled 标志")
	}
	for _, q := range f.Questions {
		d.Questions = append(d.Questions, layers.DNSQuestion{
			Name:  dnsName(q.Name),
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
	out := layers.DNSResourceRecord{
		Name:  dnsName(rr.Name),
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
		out.CNAME = dnsNameString(rr)
	case layers.DNSTypeNS:
		out.NS = dnsNameString(rr)
	case layers.DNSTypePTR:
		out.PTR = dnsNameString(rr)
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
		out.MX = layers.DNSMX{Preference: mx.Preference, Name: dnsName(mx.Exchange)}
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
			out.TXTs = append(out.TXTs, []byte(s))
		}
		if len(out.TXTs) > 0 {
			out.TXT = out.TXTs[0]
		}
	default:
		return out, fmt.Errorf("暂不支持 DNS RR 类型 %q", rr.Type)
	}
	return out, nil
}

func dnsNameString(rr scenario.DNSRRFields) []byte {
	var s string
	_ = rr.Data.Decode(&s)
	return dnsName(s)
}

func dnsName(s string) []byte {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".") // gopacket encodeName 自己补 root 终止符
	return []byte(s)
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
