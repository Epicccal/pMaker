package builder

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// OutPacket 是构造好的一个数据包:字节 + 确定性时间戳。
type OutPacket struct {
	Data []byte
	Time time.Time
}

// serOpts:最小版恒开自动修正;畸形开关(逐层关闭)是后续项。
var serOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// baseTime:固定基准,配合 index 偏移保证输出确定性(不使用 time.Now)。
var baseTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// Build 把场景模型逐包序列化为字节。
func Build(s *scenario.Scenario) ([]OutPacket, error) {
	out := make([]OutPacket, 0, len(s.Packets))
	for i, p := range s.Packets {
		data, err := buildPacket(p)
		if err != nil {
			return nil, fmt.Errorf("packet[%d]: %w", i, err)
		}
		out = append(out, OutPacket{
			Data: data,
			Time: baseTime.Add(time.Duration(i) * time.Millisecond),
		})
	}
	return out, nil
}

func buildPacket(p scenario.Packet) ([]byte, error) {
	serLayers := make([]gopacket.SerializableLayer, 0, len(p.Stack))
	var netLayer gopacket.NetworkLayer // 最近的 IP 层,供传输层 checksum 伪首部使用

	for j, l := range p.Stack {
		next := ""
		if j+1 < len(p.Stack) {
			next = p.Stack[j+1].Type
		}

		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			eth, err := buildEth(f, next)
			if err != nil {
				return nil, fmt.Errorf("eth: %w", err)
			}
			serLayers = append(serLayers, eth)
		case *scenario.VLANFields:
			serLayers = append(serLayers, buildVLAN(f, next))
		case *scenario.IPv4Fields:
			ip, err := buildIPv4(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv4: %w", err)
			}
			netLayer = ip
			serLayers = append(serLayers, ip)
		case *scenario.GREFields:
			serLayers = append(serLayers, buildGRE(next))
		case *scenario.TCPFields:
			t, err := buildTCP(f)
			if err != nil {
				return nil, fmt.Errorf("tcp: %w", err)
			}
			if netLayer != nil {
				_ = t.SetNetworkLayerForChecksum(netLayer)
			}
			serLayers = append(serLayers, t)
		case *scenario.UDPFields:
			u := &layers.UDP{SrcPort: layers.UDPPort(f.SPort), DstPort: layers.UDPPort(f.DPort)}
			if netLayer != nil {
				_ = u.SetNetworkLayerForChecksum(netLayer)
			}
			serLayers = append(serLayers, u)
		case *scenario.PayloadFields:
			b, err := payloadBytes(f)
			if err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			serLayers = append(serLayers, gopacket.Payload(b))
		case scenario.RawHex:
			b, err := hex.DecodeString(strings.ReplaceAll(string(f), " ", ""))
			if err != nil {
				return nil, fmt.Errorf("raw_hex: %w", err)
			}
			serLayers = append(serLayers, gopacket.Payload(b))
		case *scenario.DNSFields:
			d, err := buildDNS(f)
			if err != nil {
				return nil, fmt.Errorf("dns: %w", err)
			}
			serLayers = append(serLayers, d)
		case *scenario.HTTPReqFields:
			serLayers = append(serLayers, gopacket.Payload(serializeHTTPReq(f)))
		case *scenario.HTTPRespFields:
			serLayers = append(serLayers, gopacket.Payload(serializeHTTPResp(f)))
		default:
			return nil, fmt.Errorf("不支持的层类型 %q", l.Type)
		}
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serOpts, serLayers...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ethTypeFor 按下一层类型推导 EtherType。
func ethTypeFor(next string) layers.EthernetType {
	switch next {
	case "vlan":
		return layers.EthernetTypeDot1Q
	case "ipv4":
		return layers.EthernetTypeIPv4
	case "ipv6":
		return layers.EthernetTypeIPv6
	default:
		return layers.EthernetTypeIPv4
	}
}

func buildEth(f *scenario.EthFields, next string) (*layers.Ethernet, error) {
	src, err := net.ParseMAC(f.Src)
	if err != nil {
		return nil, fmt.Errorf("src mac %q: %w", f.Src, err)
	}
	dst, err := net.ParseMAC(f.Dst)
	if err != nil {
		return nil, fmt.Errorf("dst mac %q: %w", f.Dst, err)
	}
	et := ethTypeFor(next)
	if f.EtherType != nil {
		et = layers.EthernetType(uint16(*f.EtherType))
	}
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: et}, nil
}

func buildVLAN(f *scenario.VLANFields, next string) *layers.Dot1Q {
	d := &layers.Dot1Q{VLANIdentifier: f.VID}
	switch {
	case f.Type != nil: // 显式覆盖(断链)
		d.Type = layers.EthernetType(uint16(*f.Type))
	case next == "vlan" && f.TPID != nil: // 后一层标签的 TPID
		d.Type = layers.EthernetType(uint16(*f.TPID))
	default:
		d.Type = ethTypeFor(next)
	}
	return d
}

func ipProtoFor(next string) layers.IPProtocol {
	switch next {
	case "tcp":
		return layers.IPProtocolTCP
	case "udp":
		return layers.IPProtocolUDP
	case "gre":
		return layers.IPProtocolGRE
	case "ipv4":
		return layers.IPProtocolIPv4 // IP-in-IP
	default:
		return layers.IPProtocolTCP
	}
}

func buildIPv4(f *scenario.IPv4Fields, next string) (*layers.IPv4, error) {
	src := net.ParseIP(f.Src)
	dst := net.ParseIP(f.Dst)
	if src == nil || src.To4() == nil {
		return nil, fmt.Errorf("src ip %q 不是合法 IPv4", f.Src)
	}
	if dst == nil || dst.To4() == nil {
		return nil, fmt.Errorf("dst ip %q 不是合法 IPv4", f.Dst)
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
		Protocol: ipProtoFor(next),
	}
	if f.TTL != nil {
		ip.TTL = *f.TTL
	}
	if f.Protocol != nil {
		ip.Protocol = ipProtoFor(*f.Protocol)
	}
	if f.FixLengths != nil || f.Checksum != nil {
		slog.Warn("最小版忽略 ipv4 畸形开关(fix_lengths/checksum),序列化为合规包", "src", f.Src, "dst", f.Dst)
	}
	return ip, nil
}

// buildGRE:GRE.Protocol 为其载荷的 EtherType。
func buildGRE(next string) *layers.GRE {
	return &layers.GRE{Protocol: ethTypeFor(next)}
}

func buildTCP(f *scenario.TCPFields) (*layers.TCP, error) {
	t := &layers.TCP{
		SrcPort: layers.TCPPort(f.SPort),
		DstPort: layers.TCPPort(f.DPort),
		Window:  65535,
	}
	if f.Seq != nil {
		t.Seq = *f.Seq
	}
	if f.Ack != nil {
		t.Ack = *f.Ack
	}
	for _, fl := range f.Flags {
		switch strings.ToUpper(fl) {
		case "SYN":
			t.SYN = true
		case "ACK":
			t.ACK = true
		case "PSH":
			t.PSH = true
		case "FIN":
			t.FIN = true
		case "RST":
			t.RST = true
		case "URG":
			t.URG = true
		default:
			return nil, fmt.Errorf("未知 TCP flag %q", fl)
		}
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 tcp checksum 覆盖", "sport", f.SPort, "dport", f.DPort)
	}
	if f.MSS != nil {
		t.Options = append(t.Options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{byte(*f.MSS >> 8), byte(*f.MSS)},
		})
	}
	return t, nil
}

// PayloadBytes 返回一个 payload 生产层序列化后的字节。
// 供 flow 展开器取长度并按 MSS 切段(与 buildPacket 内的处理复用同一套序列化)。
func PayloadBytes(l scenario.Layer) ([]byte, error) {
	switch f := l.Fields.(type) {
	case *scenario.HTTPReqFields:
		return serializeHTTPReq(f), nil
	case *scenario.HTTPRespFields:
		return serializeHTTPResp(f), nil
	case *scenario.PayloadFields:
		return payloadBytes(f)
	case scenario.RawHex:
		return hex.DecodeString(strings.ReplaceAll(string(f), " ", ""))
	default:
		return nil, fmt.Errorf("%q 不是 payload 生产层", l.Type)
	}
}

func payloadBytes(f *scenario.PayloadFields) ([]byte, error) {
	if f.Hex != "" {
		return hex.DecodeString(strings.ReplaceAll(f.Hex, " ", ""))
	}
	return []byte(f.Text), nil
}

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

// serializeHTTPReq/Resp:把结构化 HTTP 序列化为 TCP payload 字节。
// 头按 key 排序输出以保证确定性(保留原序留待后续)。
func serializeHTTPReq(f *scenario.HTTPReqFields) []byte {
	method := orDefault(f.Method, "GET")
	url := orDefault(f.Url, "/")
	ver := orDefault(f.Version, "HTTP/1.1")

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, url, ver)
	writeHeaders(&b, f.Headers, len(f.Body))
	b.WriteString("\r\n")
	b.WriteString(f.Body)
	return []byte(b.String())
}

func serializeHTTPResp(f *scenario.HTTPRespFields) []byte {
	ver := orDefault(f.Version, "HTTP/1.1")
	status := f.Status
	if status == 0 {
		status = 200
	}
	reason := orDefault(f.Reason, http.StatusText(status))

	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", ver, status, reason)
	writeHeaders(&b, f.Headers, len(f.Body))
	b.WriteString("\r\n")
	b.WriteString(f.Body)
	return []byte(b.String())
}

func writeHeaders(b *strings.Builder, h map[string]string, bodyLen int) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := h[k]
		if strings.EqualFold(k, "Content-Length") && v == "auto" {
			v = strconv.Itoa(bodyLen)
		}
		fmt.Fprintf(b, "%s: %s\r\n", k, v)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
