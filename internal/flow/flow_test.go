package flow_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// genFlow 跑完整链路:load -> plan.Plan(汇流+排序)-> BuildPlanned -> writer,返回 pcap 字节。
func genFlow(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes()
}

func readTCP(t *testing.T, data []byte) []*layers.TCP {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	var tcps []*layers.TCP
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeTCP); l != nil {
			tcps = append(tcps, l.(*layers.TCP))
		}
	}
	return tcps
}

// TestFlowShape 校验握手/挥手标志、包数、SYN 携带 MSS option、应用层字节。
func TestFlowShape(t *testing.T) {
	data := genFlow(t, "../../examples/http/get.yaml")
	tcps := readTCP(t, data)
	if len(tcps) != 11 {
		t.Fatalf("期望 11 个 TCP 包,得到 %d", len(tcps))
	}

	// 握手:SYN / SYN,ACK / ACK
	if !tcps[0].SYN || tcps[0].ACK {
		t.Error("包0 应为纯 SYN")
	}
	if !tcps[1].SYN || !tcps[1].ACK {
		t.Error("包1 应为 SYN,ACK")
	}
	if tcps[2].SYN || !tcps[2].ACK {
		t.Error("包2 应为纯 ACK")
	}

	// SYN / SYN,ACK 必须带 MSS option = 1460
	for _, i := range []int{0, 1} {
		if mss := mssOption(tcps[i]); mss != 1460 {
			t.Errorf("包%d 的通告 MSS = %d,期望 1460", i, mss)
		}
	}
	if mssOption(tcps[2]) != 0 {
		t.Error("非 SYN 包不应带 MSS option")
	}

	// 收尾:两个 FIN、两个 PSH(请求/响应各一段)
	fin, psh := 0, 0
	for _, tc := range tcps {
		if tc.FIN {
			fin++
		}
		if tc.PSH {
			psh++
		}
	}
	if fin != 2 || psh != 2 {
		t.Errorf("FIN=%d PSH=%d,期望 2/2", fin, psh)
	}

	// 应用层字节:请求行与响应体
	if !bytes.Contains(data, []byte("GET /index.html HTTP/1.1")) {
		t.Error("未见 HTTP 请求行")
	}
	if !bytes.Contains(data, []byte("Hello from pMaker")) {
		t.Error("未见响应体")
	}
}

// TestFlowSeqSegmentation 校验分段后各段 seq 连续且 = ISN+1+字节偏移(钉住状态机与分段)。
func TestFlowSeqSegmentation(t *testing.T) {
	mss := uint16(1460)
	f := scenario.FlowSpec{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000, MSS: &mss}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
		},
		Messages: []scenario.Message{{
			From: "src",
			Stack: []scenario.Layer{{
				Type:   "payload_hex",
				Fields: scenario.PayloadHex("0x" + hex.EncodeToString(make([]byte, 20))), // 20 字节,mss=8 → 8/8/4 三段
			}},
			Segment: &scenario.Segment{MSS: 8},
		}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	// 收集 client 侧带 payload 的数据段(PSH),断言 seq = 1001, 1009, 1017
	var seqs []uint32
	for _, p := range pkts {
		tc := tcpOf(p.Packet)
		if tc != nil && contains(tc.Flags, "PSH") && tc.Seq != nil {
			seqs = append(seqs, *tc.Seq)
		}
	}
	want := []uint32{1001, 1009, 1017} // ISN(1000)+SYN(1)=1001 起,按 8 字节偏移
	if len(seqs) != len(want) {
		t.Fatalf("期望 3 段,得到 %d(%v)", len(seqs), seqs)
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Errorf("段%d seq=%d,期望 %d", i, seqs[i], want[i])
		}
	}
}

// TestFlowExpandMessageIDTimes 校验 Expand 第三返回值:显式设了 message_id 的消息,
// 其映射值 = 该消息整组完成时刻 msgCursor(= 对端 ACK + DefaultStep),未设的不收录。
func TestFlowExpandMessageIDTimes(t *testing.T) {
	f := scenario.FlowSpec{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
		},
		Messages: []scenario.Message{
			{From: "src", MessageID: "m1", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa"}}}},
			{From: "dst", MessageID: "m2", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "bbbb"}}}},
		},
	}
	_, _, msgids, err := flow.Expand(f, time.Time{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// 握手占 0/1/2ms;m1 start=3ms,数据段@3,ACK@4,完成 msgCursor=5ms;
	// m2 start=5ms,数据段@5,ACK@6,完成 msgCursor=7ms。锚为 time.Time{}(零时刻)。
	zero := time.Time{}
	want := map[string]time.Time{
		"m1": zero.Add(5 * time.Millisecond),
		"m2": zero.Add(7 * time.Millisecond),
	}
	if len(msgids) != len(want) {
		t.Fatalf("期望 %d 个具名消息,得到 %d(%v)", len(want), len(msgids), msgids)
	}
	for k, w := range want {
		got, ok := msgids[k]
		if !ok {
			t.Errorf("缺少 message_id %q", k)
			continue
		}
		if !got.Equal(w) {
			t.Errorf("message_id %q 时刻=%v,期望 %v", k, got, w)
		}
	}
}

// TestFlowCloseRST 校验 close:rst 由 server 单包中断,不再生成 FIN 挥手。
func TestFlowCloseRST(t *testing.T) {
	f := scenario.FlowSpec{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "rst"}},
		},
		Messages: []scenario.Message{{
			From: "src",
			Stack: []scenario.Layer{{
				Type:   "payload_hex",
				Fields: scenario.PayloadHex("0xabcd"),
			}},
		}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(pkts) != 6 { // 握手3 + 数据1 + ACK1 + RST1
		t.Fatalf("期望 6 个包,得到 %d", len(pkts))
	}
	last := tcpOf(pkts[len(pkts)-1].Packet)
	if last == nil || !contains(last.Flags, "RST") || !contains(last.Flags, "ACK") {
		t.Fatalf("最后一个包应为 RST,ACK,得到 %#v", last)
	}
	for i, p := range pkts {
		if tc := tcpOf(p.Packet); tc != nil && contains(tc.Flags, "FIN") {
			t.Fatalf("close:rst 不应生成 FIN,但包%d 含 FIN", i)
		}
	}
}

func TestFlowSummaryKeepsApplicationProtocol(t *testing.T) {
	s, err := scenario.Load("../../examples/http/get.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, f := range s.Flows {
		fp, _, _, err := flow.Expand(f, time.Time{})
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		for _, pp := range fp {
			s.Packets = append(s.Packets, pp.Packet)
		}
	}

	summaries := scenario.SummarizePackets(s.Packets)
	if len(summaries) < 6 {
		t.Fatalf("摘要数量=%d,期望至少 6", len(summaries))
	}
	want := map[int]string{
		4: "[4] 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp/http",
		6: "[6] 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp/http",
	}
	for n, w := range want {
		if line := scenario.FormatPacketSummary(n, summaries[n-1]); line != w {
			t.Errorf("第%d行=%q,期望 %q", n, line, w)
		}
	}
}

func mssOption(tc *layers.TCP) uint16 {
	for _, o := range tc.Options {
		if o.OptionType == layers.TCPOptionKindMSS && len(o.OptionData) == 2 {
			return uint16(o.OptionData[0])<<8 | uint16(o.OptionData[1])
		}
	}
	return 0
}

func tcpOf(p scenario.Packet) *scenario.TCPFields {
	for _, l := range p.Stack {
		if t, ok := l.Fields.(*scenario.TCPFields); ok {
			return t
		}
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
