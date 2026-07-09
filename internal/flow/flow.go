package flow

import (
	"encoding/hex"
	"fmt"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

type side int

const (
	sideSrc side = iota
	sideDst
)

func (s side) peer() side {
	if s == sideSrc {
		return sideDst
	}
	return sideSrc
}

type endpoint struct {
	mac  string
	ip   string
	port uint16
}

type session struct {
	open  string
	close string
}

// conn 维护会话状态:src 是 TCP SYN 发起方,dst 是 SYN 接收方。
type conn struct {
	src, dst       endpoint
	ttl            *uint8
	srcSeq, dstSeq uint32
	mss            *uint16
	session        session
}

// Expand 把一条 flow 展开成有序的 stack 包。
//
// 当前 flow.stack 支持 eth/ipv4/tcp/tcp_session;VLAN/GRE 等会话封装后续扩展。
func Expand(f scenario.FlowSpec) ([]scenario.Packet, error) {
	c, err := parseFlowStack(f.Stack)
	if err != nil {
		return nil, err
	}
	var out []scenario.Packet

	// 三次握手(SYN / SYN,ACK 携带通告 MSS)
	if c.session.open == "" || c.session.open == "handshake" {
		out = append(out,
			c.emit(sideSrc, []string{"SYN"}, nil),
			c.emit(sideDst, []string{"SYN", "ACK"}, nil),
			c.emit(sideSrc, []string{"ACK"}, nil),
		)
	}

	// 应用层消息:按 segment.mss 切段发送,对端按 per-message 回一个 ACK
	for _, m := range f.Messages {
		b, err := messagePayload(m)
		if err != nil {
			return nil, err
		}
		from := sideOf(m.From)
		for _, seg := range split(b, segMSS(m)) {
			out = append(out, c.emit(from, []string{"PSH", "ACK"}, seg))
		}
		out = append(out, c.emit(from.peer(), []string{"ACK"}, nil))
	}

	// 关闭:默认四次挥手;rst 表示对端(dst)单包中断连接。
	switch c.session.close {
	case "", "fin":
		out = append(out,
			c.emit(sideSrc, []string{"FIN", "ACK"}, nil),
			c.emit(sideDst, []string{"ACK"}, nil),
			c.emit(sideDst, []string{"FIN", "ACK"}, nil),
			c.emit(sideSrc, []string{"ACK"}, nil),
		)
	case "rst":
		out = append(out, c.emit(sideDst, []string{"RST", "ACK"}, nil))
	}
	return out, nil
}

func parseFlowStack(stack []scenario.Layer) (*conn, error) {
	c := &conn{}
	for _, l := range stack {
		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			c.src.mac, c.dst.mac = f.Src, f.Dst
		case *scenario.IPv4Fields:
			c.src.ip, c.dst.ip = f.Src, f.Dst
			c.ttl = f.TTL
		case *scenario.TCPFields:
			c.src.port, c.dst.port = f.SPort, f.DPort
			c.srcSeq, c.dstSeq = f.ClientISN, f.ServerISN
			c.mss = f.MSS
		case *scenario.TCPSessionFields:
			c.session = session{open: f.Open, close: f.Close}
		default:
			return nil, fmt.Errorf("flow.stack 暂不支持 %q", l.Type)
		}
	}
	if c.src.mac == "" || c.dst.mac == "" || c.src.ip == "" || c.dst.ip == "" || c.src.port == 0 || c.dst.port == 0 {
		return nil, fmt.Errorf("flow.stack 需要 eth/src-dst、ipv4/src-dst、tcp/sport-dport")
	}
	return c, nil
}

// emit 发一个方向的段:填 seq/ack、推进状态,产出一个 stack 包。
func (c *conn) emit(from side, flags []string, chunk []byte) scenario.Packet {
	var seq, ack uint32
	if from == sideSrc {
		seq, ack = c.srcSeq, c.dstSeq
	} else {
		seq, ack = c.dstSeq, c.srcSeq
	}

	// seq 前进量 = payload 字节 + SYN(1) + FIN(1);纯 ACK/RST 不前进。
	adv := uint32(len(chunk))
	if hasFlag(flags, "SYN") {
		adv++
	}
	if hasFlag(flags, "FIN") {
		adv++
	}
	if from == sideSrc {
		c.srcSeq += adv
	} else {
		c.dstSeq += adv
	}

	src, dst := c.src, c.dst
	if from == sideDst {
		src, dst = c.dst, c.src
	}

	tcp := &scenario.TCPFields{
		SPort: src.port,
		DPort: dst.port,
		Flags: flags,
		Seq:   &seq,
		Ack:   &ack,
	}
	if hasFlag(flags, "SYN") && c.mss != nil {
		tcp.MSS = c.mss
	}

	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: src.mac, Dst: dst.mac}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: src.ip, Dst: dst.ip, TTL: c.ttl}},
		{Type: "tcp", Fields: tcp},
	}
	if len(chunk) > 0 {
		stack = append(stack, scenario.Layer{
			Type:   "payload_hex",
			Fields: scenario.PayloadHex("0x" + hex.EncodeToString(chunk)),
		})
	}
	return scenario.Packet{Stack: stack}
}

func messagePayload(m scenario.Message) ([]byte, error) {
	if len(m.Stack) != 1 {
		return nil, fmt.Errorf("message.stack 当前需恰好一个 payload 生产层")
	}
	return builder.PayloadBytes(m.Stack[0])
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
	if s == "dst" {
		return sideDst
	}
	return sideSrc
}
