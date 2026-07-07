package flow

import (
	"encoding/hex"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

type side int

const (
	sideClient side = iota
	sideServer
)

func (s side) peer() side {
	if s == sideClient {
		return sideServer
	}
	return sideClient
}

// conn 维护会话状态:两方向各一个 seq(全程 uint32 加法,天然回绕),ack 由推导得到。
type conn struct {
	client, server scenario.Endpoint
	cliSeq, srvSeq uint32
	mss            *uint16
}

// Expand 把一条 flow 展开成有序的 stack 包。
//
// ponytail: 当前降解为 []scenario.Packet 并借用 builder 的 index 时间戳;要做多流时间交织 /
// RTT 定时时,升级为 []PlannedPacket 统一入口(见 CLAUDE.md「flow 场景设计」)。
func Expand(f scenario.FlowSpec) ([]scenario.Packet, error) {
	c := &conn{
		client: f.Client,
		server: f.Server,
		cliSeq: f.TCP.ClientISN,
		srvSeq: f.TCP.ServerISN,
		mss:    f.TCP.MSS,
	}
	var out []scenario.Packet

	// 三次握手(SYN / SYN,ACK 携带通告 MSS)
	if f.Open == "" || f.Open == "handshake" {
		out = append(out,
			c.emit(sideClient, []string{"SYN"}, nil),
			c.emit(sideServer, []string{"SYN", "ACK"}, nil),
			c.emit(sideClient, []string{"ACK"}, nil),
		)
	}

	// 应用层消息:按 segment.mss 切段发送,对端按 per-message 回一个 ACK
	for _, m := range f.Messages {
		b, err := builder.PayloadBytes(messageLayer(m))
		if err != nil {
			return nil, err
		}
		from := sideOf(m.From)
		for _, seg := range split(b, segMSS(m)) {
			out = append(out, c.emit(from, []string{"PSH", "ACK"}, seg))
		}
		out = append(out, c.emit(from.peer(), []string{"ACK"}, nil))
	}

	// 四次挥手(client 发起)
	if f.Close == "" || f.Close == "fin" {
		out = append(out,
			c.emit(sideClient, []string{"FIN", "ACK"}, nil),
			c.emit(sideServer, []string{"ACK"}, nil),
			c.emit(sideServer, []string{"FIN", "ACK"}, nil),
			c.emit(sideClient, []string{"ACK"}, nil),
		)
	}
	return out, nil
}

// emit 发一个方向的段:填 seq/ack、推进状态,产出一个 stack 包。
func (c *conn) emit(from side, flags []string, chunk []byte) scenario.Packet {
	var seq, ack uint32
	if from == sideClient {
		seq, ack = c.cliSeq, c.srvSeq
	} else {
		seq, ack = c.srvSeq, c.cliSeq
	}

	// seq 前进量 = payload 字节 + SYN(1) + FIN(1);纯 ACK 不前进。
	adv := uint32(len(chunk))
	if hasFlag(flags, "SYN") {
		adv++
	}
	if hasFlag(flags, "FIN") {
		adv++
	}
	if from == sideClient {
		c.cliSeq += adv
	} else {
		c.srvSeq += adv
	}

	src, dst := c.client, c.server
	if from == sideServer {
		src, dst = c.server, c.client
	}

	tcp := &scenario.TCPFields{
		SPort: src.Port,
		DPort: dst.Port,
		Flags: flags,
		Seq:   &seq,
		Ack:   &ack,
	}
	if hasFlag(flags, "SYN") && c.mss != nil {
		tcp.MSS = c.mss
	}

	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: src.MAC, Dst: dst.MAC}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: src.IP, Dst: dst.IP}},
		{Type: "tcp", Fields: tcp},
	}
	if len(chunk) > 0 {
		stack = append(stack, scenario.Layer{
			Type:   "payload",
			Fields: &scenario.PayloadFields{Hex: hex.EncodeToString(chunk)},
		})
	}
	return scenario.Packet{Stack: stack}
}

func messageLayer(m scenario.Message) scenario.Layer {
	switch {
	case m.HTTPRequest != nil:
		return scenario.Layer{Type: "http_request", Fields: m.HTTPRequest}
	case m.HTTPResponse != nil:
		return scenario.Layer{Type: "http_response", Fields: m.HTTPResponse}
	case m.Payload != nil:
		return scenario.Layer{Type: "payload", Fields: m.Payload}
	default:
		return scenario.Layer{Type: "raw_hex", Fields: scenario.RawHex(m.RawHex)}
	}
}

func segMSS(m scenario.Message) int {
	if m.Segment != nil {
		return m.Segment.MSS
	}
	return 0
}

// split 按 mss 把字节切成多段;mss<=0 或不足一段时整条返回。
func split(b []byte, mss int) [][]byte {
	if mss <= 0 || len(b) <= mss {
		return [][]byte{b}
	}
	var segs [][]byte
	for len(b) > mss {
		segs = append(segs, b[:mss])
		b = b[mss:]
	}
	return append(segs, b)
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func sideOf(s string) side {
	if s == "server" {
		return sideServer
	}
	return sideClient
}
