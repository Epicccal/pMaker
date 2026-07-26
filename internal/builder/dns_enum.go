package builder

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// 本文件收录 DNS 字符串 ↔ 枚举的纯映射函数(type/class/opcode/rcode/qr)及
// RR 编号解析、域名校验,与 dns.go 的构包逻辑分离。这些函数不触碰 scenario
// 模型,只做字符串到 gopacket 枚举值的翻译,便于独立阅读与测试。

// dnsType 解析 RR/QType 字符串。接受三种写法:
//   - 省略 → 默认 A
//   - 已知名字(A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV)→ 对应 DNSType
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
	case "SOA":
		return layers.DNSTypeSOA, nil
	case "SRV":
		return layers.DNSTypeSRV, nil
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
