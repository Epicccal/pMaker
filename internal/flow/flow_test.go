package flow_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
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
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil, nil)
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
	_, _, msgids, err := flow.Expand(f, time.Time{}, nil, nil)
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
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil, nil)
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

// TestFlowMessageMultiPayload 校验一条 message 装多个 payload 生产层时,
// 各层按栈声明顺序拼接进同一个 TCP 段:两个 payload 层 "aaaa"+"bbbb" → 段内 "aaaabbbb",
// seq 推进量 = 8(= 拼接后总字节,与 standalone packet 多 payload 层语义一致)。
func TestFlowMessageMultiPayload(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Flows: []scenario.FlowSpec{{
			Name: "multi",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
			},
			Messages: []scenario.Message{{
				From: "src",
				Stack: []scenario.Layer{
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa"}},
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "bbbb"}},
				},
			}},
		}},
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
	tcps := readTCP(t, buf.Bytes())

	// 找唯一的 PSH 数据段(client→server),断言 payload == "aaaabbbb"。
	var dataSeg *layers.TCP
	for _, tc := range tcps {
		if tc.PSH && len(tc.Payload) > 0 && tc.SrcPort == 1111 {
			dataSeg = tc
			break
		}
	}
	if dataSeg == nil {
		t.Fatalf("未找到 client→server 的 PSH 数据段")
	}
	if string(dataSeg.Payload) != "aaaabbbb" {
		t.Errorf("数据段 payload=%q,期望 \"aaaabbbb\"(两个 payload 层按栈序拼接)", string(dataSeg.Payload))
	}
	// 只应有一个 client→server 数据段(未设 mss,整条不切)。
	count := 0
	for _, tc := range tcps {
		if tc.PSH && len(tc.Payload) > 0 && tc.SrcPort == 1111 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("client→server 数据段数=%d,期望 1(拼接后整段不切)", count)
	}
}

// TestFlowMessagePayloadEmptyStack 走完整链路钉 messagePayload 对空 stack 报错:
// Validate 已拦空 stack,这里通过解析 YAML 让 message.stack 为空触发 messagePayload 守护
// (Validate 不在测试链路,直接走 plan.Plan → flow.Expand → messagePayload)。
func TestFlowMessagePayloadEmptyStack(t *testing.T) {
	// 构造一个 stack 为空的 message:不经过 Validate,直接喂 plan.Plan。
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Flows: []scenario.FlowSpec{{
			Name: "empty",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
			},
			Messages: []scenario.Message{{From: "src", Stack: nil}},
		}},
	}
	// plan.Plan 不跑 Validate,直接展开 flow;空 stack 在 messagePayload 守护处报错。
	_, err := plan.Plan(s)
	if err == nil || !strings.Contains(err.Error(), "至少一个 payload 生产层") {
		t.Fatalf("空 message.stack 应报错,得到 %v", err)
	}
}

// TestFlowMessagePayloadLayerError 钉 messagePayload 逐层取字节时,某层构建失败
// 会带层索引上抛(如 PayloadHex 非法)。多 payload 层遍历路径(循环内 return err 分支)覆盖。
func TestFlowMessagePayloadLayerError(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Flows: []scenario.FlowSpec{{
			Name: "badlayer",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
			},
			Messages: []scenario.Message{{
				From: "src",
				Stack: []scenario.Layer{
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "aaaa"}}, // stack[0] 正常
					{Type: "payload_hex", Fields: scenario.PayloadHex("0xZZ")},          // stack[1] 非法 hex
				},
			}},
		}},
	}
	_, err := plan.Plan(s)
	if err == nil || !strings.Contains(err.Error(), "message.stack[1]") {
		t.Fatalf("第二层构建失败应带层索引 message.stack[1] 上抛,得到 %v", err)
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
		fp, _, _, err := flow.Expand(f, time.Time{}, nil, nil)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		for _, pp := range fp {
			s.Packets = append(s.Packets, pp.Packet)
		}
	}

	summaries := summary.SummarizePackets(s.Packets)
	if len(summaries) < 6 {
		t.Fatalf("摘要数量=%d,期望至少 6", len(summaries))
	}
	want := map[int]string{
		4: "[4] 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp/http",
		6: "[6] 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp/http",
	}
	for n, w := range want {
		if line := summary.FormatPacketSummary(n, summaries[n-1]); line != w {
			t.Errorf("第%d行=%q,期望 %q", n, line, w)
		}
	}
}

// TestFTPPasvRetrShape 回读 pasv_retr,验证合流后是两条独立五元组的 TCP 流(用 sport 区分),
// 且数据通道的 sport/dport 与控制连接不同(端口角色独立)。shape(端口/握手)放 flow 层验证;
// 跨流时序(150<data<226)在 scenario 层 TestFTPPasvRetrTiming 单独断言——flow.Expand 单 flow
// 无跨流概念。
func TestFTPPasvRetrShape(t *testing.T) {
	data := genFlow(t, "../../examples/ftp/pasv_retr.yaml")
	tcps := readTCP(t, data)
	sports := map[uint16]bool{}
	for _, tc := range tcps {
		sports[uint16(tc.SrcPort)] = true
	}
	// 控制连接 sport=49154、数据连接 sport=49155(以及反向 21 / 50000)各自独立。
	if !sports[49154] {
		t.Errorf("缺少控制连接 sport=49154 的包(独立五元组未生成)")
	}
	if !sports[49155] {
		t.Errorf("缺少数据通道 sport=49155 的包(独立五元组未生成)")
	}
	// 两条流都应有自己的握手 SYN(各开 open=handshake)。
	synBySport := map[uint16]int{}
	for _, tc := range tcps {
		if tc.SYN && !tc.ACK {
			synBySport[uint16(tc.SrcPort)]++
		}
	}
	for _, sp := range []uint16{49154, 49155} {
		if synBySport[sp] == 0 {
			t.Errorf("sport=%d 缺少自己的 SYN(握手),两条流应各自独立握手", sp)
		}
	}
}

// TestFTPPortStorShape 回读 port_stor,验证主动模式:服务器从 20 端口发起数据连接 SYN
// (data 流 src=服务器,整条 stack 反转),数据通道 sport=20、dport=49157,与控制连接不同。
func TestFTPPortStorShape(t *testing.T) {
	data := genFlow(t, "../../examples/ftp/port_stor.yaml")
	tcps := readTCP(t, data)
	// 控制连接 49156<->21;数据连接由服务器(20)主动连客户端(49157)。
	var dataSYN *layers.TCP
	for _, tc := range tcps {
		if tc.SYN && !tc.ACK && uint16(tc.SrcPort) == 20 && uint16(tc.DstPort) == 49157 {
			dataSYN = tc
			break
		}
	}
	if dataSYN == nil {
		t.Fatalf("未找到主动模式数据通道 SYN(sport=20 -> dport=49157,应由服务器发起)")
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
	return slices.Contains(ss, s)
}
