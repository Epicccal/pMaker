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
	return t, nil
}

func payloadBytes(f *scenario.PayloadFields) ([]byte, error) {
	if f.Hex != "" {
		return hex.DecodeString(strings.ReplaceAll(f.Hex, " ", ""))
	}
	return []byte(f.Text), nil
}

// serializeHTTPReq/Resp:把结构化 HTTP 序列化为 TCP payload 字节。
// 头按 key 排序输出以保证确定性(保留原序留待后续)。
func serializeHTTPReq(f *scenario.HTTPReqFields) []byte {
	method := orDefault(f.Method, "GET")
	target := orDefault(f.Target, "/")
	ver := orDefault(f.Version, "HTTP/1.1")

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, target, ver)
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
