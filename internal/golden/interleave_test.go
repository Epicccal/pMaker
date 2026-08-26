package golden_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// TestInterleaveFlowStart 验证显式时间 + 汇流排序:
// 声明序为 [late-syn@30ms, flow@0ms/1ms],写盘应按时间升序为 flow、flow-ack、late-syn。
func TestInterleaveFlowStart(t *testing.T) {
	pcap := generatePcap(t, "../../examples/interleave/flow_start.yaml")
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	type rec struct {
		ts  time.Time
		syn bool
	}
	var recs []rec
	for {
		raw, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		tcp := p.Layer(layers.LayerTypeTCP)
		recs = append(recs, rec{ts: ci.Timestamp, syn: tcp != nil && tcp.(*layers.TCP).SYN})
	}
	if len(recs) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(recs))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Duration{0, time.Millisecond, 30 * time.Millisecond}
	for i, w := range want {
		got := recs[i].ts.Sub(base)
		if got != w {
			t.Errorf("包%d 时间偏移=%v,期望 %v", i, got, w)
		}
	}
	// 前两个是 flow 的数据段 + ACK(均非 SYN),末尾是 late-syn(纯 SYN)。
	if !recs[2].syn {
		t.Errorf("末包期望为 SYN(late-syn),实际非 SYN")
	}
	if recs[0].syn || recs[1].syn {
		t.Errorf("前两包不应为 SYN(应为 flow 数据/ACK)")
	}
}

// TestInterleaveCrossFlowIndependence 验证跨流时间独立(新模型:跨流独立 + 流内顺序):
// flow-A 内部一条消息用 offset_time:+5s 钉到自己,flow-B 无 offset 在 base 起步并发——
// 不被 flow-A 的 5s 迟到请求拖到其后。关键断言:flow-B 的 SYN 出现在 base+0ms(与 flow-A
// 握手并发),远早于 flow-A 的迟到请求(base+5.003s)——两条独立流并行,flow-B 不等 flow-A。
func TestInterleaveCrossFlowIndependence(t *testing.T) {
	pcap := generatePcap(t, "../../examples/interleave/cross_flow_independence.yaml")
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	type rec struct {
		ts           time.Time
		syn          bool
		sport, dport uint16
	}
	var recs []rec
	for {
		raw, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		var sport, dport uint16
		syn := false
		if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
			tc := tcp.(*layers.TCP)
			syn = tc.SYN
			sport, dport = uint16(tc.SrcPort), uint16(tc.DstPort)
		}
		recs = append(recs, rec{ts: ci.Timestamp, syn: syn, sport: sport, dport: dport})
	}
	if len(recs) != 24 {
		t.Fatalf("期望 24 个包,得到 %d", len(recs))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// flow-A 的 SYN(sport=49152)在 base+0ms;flow-B 的 SYN(sport=49153)也在 base+0ms
	// (无 offset,在 base 并发起步,不接续 flow-A)。
	var flowBSYN time.Time
	for _, r := range recs {
		if r.syn && r.sport == 49153 {
			flowBSYN = r.ts
			break
		}
	}
	if flowBSYN.IsZero() {
		t.Fatal("未找到 flow-B 的 SYN(sport=49153)")
	}
	if got := flowBSYN.Sub(base); got != 0 {
		t.Errorf("flow-B SYN 偏移=%v,期望 0(无 offset 在 base 并发起步);若为 5s+ 则被跨流劫持", got)
	}

	// flow-A 的迟到请求(sport=49152, GET /late)在 base+5.003s,应在 flow-B 的 SYN 之后,
	// 即两条流时间交错(flow-B 不等 flow-A 的迟到包)。
	var lateReq time.Time
	for _, r := range recs {
		if r.sport == 49152 && r.ts.Sub(base) > 4*time.Second { // +5s 插队包
			lateReq = r.ts
			break
		}
	}
	if lateReq.IsZero() {
		t.Fatal("未找到 flow-A 的迟到请求(GET /late)")
	}
	if !lateReq.After(flowBSYN) {
		t.Errorf("flow-A 迟到请求(%v) 应在 flow-B SYN(%v) 之后(时间交错)", lateReq, flowBSYN)
	}
}

// TestMessageStartAfter 验证 message 级 start_after:data 流的 RETR 消息等 control.pasv
// 整组完成(msgCursor)后才发,而非紧接 data 流内的上一条 GREETING。
//
// 时间线(open=none,base=2024-01-01T00:00:00Z):
//
//	control PASV-req data@base/ack@+1;  PASV-227 data@+2/ack@+3,msgCursor=+4(message_id: pasv)
//	data GREETING data@base/ack@+1,msgCursor=+2(默认链式,不等 control)
//	data RETR    start_after control.pasv → 锚 base+4;data@+4/ack@+5
func TestMessageStartAfter(t *testing.T) {
	pcap := generatePcap(t, "../../examples/interleave/message_start_after.yaml")
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	type rec struct {
		ts      time.Time
		sport   uint16
		payload bool
	}
	var recs []rec
	for {
		raw, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		tcpL := p.Layer(layers.LayerTypeTCP)
		var sp uint16
		if tcpL != nil {
			sp = uint16(tcpL.(*layers.TCP).SrcPort)
		}
		// 用应用层 payload 是否存在区分数据段(PSH+数据)与纯 ACK。
		recs = append(recs, rec{ts: ci.Timestamp, sport: sp, payload: p.ApplicationLayer() != nil})
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// 端口:control 用 49152/21;data 的 src=49153、dst=50000。
	// GREETING from=dst → sport=50000;RETR from=src → sport=49153。只看带 payload 的数据段。
	var retr, greeting time.Time
	for _, r := range recs {
		if !r.payload {
			continue
		}
		switch r.sport {
		case 50000: // data 的 GREETING(服务端发出)
			if greeting.IsZero() {
				greeting = r.ts
			}
		case 49153: // data 的 RETR(客户端发出)
			if retr.IsZero() {
				retr = r.ts
			}
		}
	}
	if greeting.IsZero() || retr.IsZero() {
		t.Fatalf("未找到 data 的两条数据段: greeting=%v retr=%v", greeting, retr)
	}
	// GREETING 紧接 base(data 流锚,无 start_after)。
	if got := greeting.Sub(base); got != 0 {
		t.Errorf("GREETING 偏移=%v,期望 0(紧接 data 流锚)", got)
	}
	// RETR 锚到 control.pasv 完成时刻(msgCursor=base+4)。
	if got := retr.Sub(base); got != 4*time.Millisecond {
		t.Errorf("RETR 偏移=%v,期望 4ms(= control.pasv msgCursor)", got)
	}
	// RETR 必须晚于 GREETING(否则 start_after 未生效)。
	if !retr.After(greeting) {
		t.Errorf("RETR(%v) 应在 GREETING(%v) 之后(start_after 生效)", retr, greeting)
	}
}
