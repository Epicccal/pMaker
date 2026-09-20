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
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
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
	_, _, msgids, err := flow.Expand(f, time.Time{}, nil)
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
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
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
	var planned []scenario.PlannedPacket
	for _, f := range s.Flows {
		fp, _, _, err := flow.Expand(f, time.Time{}, nil)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		planned = append(planned, fp...)
	}

	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	summaries := summary.SummarizeOut(planned, pkts)
	if len(summaries) < 6 {
		t.Fatalf("摘要数量=%d,期望至少 6", len(summaries))
	}
	want := map[int]string{
		4: "10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp/http",
		6: "10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp/http",
	}
	lines := summary.FormatPacketSummaries(summaries)
	for n, w := range want {
		if !strings.Contains(lines[n-1], w) {
			t.Errorf("第%d行=%q,期望包含 %q", n, lines[n-1], w)
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

// TestFlowVLANEncapsulation 回读 vlan 封装 flow:每个展开包(握手/数据/挥手)都重建
// vlan 标签链(eth 之后、ipv4 之前),反向消息方向反转后标签链保持不变
// (vid/type 无方向性),QinQ 多层按声明序。钉住 parseFlowStack 记录 + emit 重建。
func TestFlowVLANEncapsulation(t *testing.T) {
	mss := uint16(1460)
	innerTPID := scenario.Hex(0x8100)
	f := scenario.FlowSpec{
		Name: "vlan-qinq",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
			{Type: "vlan", Fields: &scenario.VLANFields{VID: 200, Type: &innerTPID}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000, MSS: &mss}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
		},
		Messages: []scenario.Message{{
			From:  "src",
			Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "hello"}}},
		}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	// 每个展开包:eth 打头、两条 vlan(vid 100/200)、随后 ipv4/tcp;
	// vlan.type 非空时原样落值(非标标签间 TPID),方向反转不改标签链。
	for i, p := range pkts {
		var vlans []*scenario.VLANFields
		for _, l := range p.Stack {
			if v, ok := l.Fields.(*scenario.VLANFields); ok {
				vlans = append(vlans, v)
			}
		}
		if len(vlans) != 2 {
			t.Fatalf("包%d 应有 2 层 vlan,得到 %d", i, len(vlans))
		}
		if vlans[0].VID != 100 {
			t.Errorf("包%d 外层 vid=%d,期望 100", i, vlans[0].VID)
		}
		if vlans[1].VID != 200 {
			t.Errorf("包%d 内层 vid=%d,期望 200", i, vlans[1].VID)
		}
		if vlans[1].Type == nil || *vlans[1].Type != innerTPID {
			t.Errorf("包%d 内层 type 应为显式 0x8100,得到 %v", i, vlans[1].Type)
		}
		// 栈相对位置:eth(0) → vlan… → ipv4(网络层在 vlan 之后)
		if p.Stack[0].Type != "eth" || p.Stack[1].Type != "vlan" || p.Stack[3].Type != "ipv4" {
			t.Errorf("包%d 栈顺序不是 eth → vlan… → ipv4", i)
		}
	}
}

// TestFlowVLANBeforeEthRejected: vlan 写在 eth 之前 → validateFlow 拦截。
// 含最外层(i==0)与栈中段在 eth 前(如 [tcp, vlan, eth, …])两种:后者旧检查只判
// i==0 会放过,声明序非 eth 开头时 emit 重建会无声重排,故须以 ethIdx 相对位置拦截。
func TestFlowVLANBeforeEthRejected(t *testing.T) {
	cases := []struct {
		name  string
		stack []scenario.Layer
	}{
		{
			name: "vlan 最外层",
			stack: []scenario.Layer{
				{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			},
		},
		{
			name: "vlan 在栈中段但先于 eth",
			stack: []scenario.Layer{
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
				{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1112, DPort: 8080}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			},
		},
	}
	base := scenario.FlowSpec{
		Messages: []scenario.Message{{
			From:  "src",
			Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.Stack = tc.stack
			s := &scenario.Scenario{Flows: []scenario.FlowSpec{f}}
			err := scenario.Validate(s)
			if err == nil || !strings.Contains(err.Error(), "层序须为") {
				t.Fatalf("Validate() error=%v,期望拒绝 eth 之前的 vlan", err)
			}
		})
	}
}

// TestFlowVLANAfterNetworkRejected: vlan 写在网络层之后 → validateFlow 拦截
// (wire 上标签必须紧贴以太头,网络层之后无法成帧)。
func TestFlowVLANAfterNetworkRejected(t *testing.T) {
	s := &scenario.Scenario{
		Flows: []scenario.FlowSpec{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			},
			Messages: []scenario.Message{{
				From:  "src",
				Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}}},
			}},
		}},
	}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "层序须为") {
		t.Fatalf("Validate() error=%v,期望拒绝网络层之后的 vlan", err)
	}
}

// ---------- 方向化 VLAN VID(src_vid / dst_vid)----------

// vlanVIDs 收集一个展开包里 vlan 层的 VID 序列(外→内)。
func vlanVIDs(p scenario.Packet) []uint16 {
	var out []uint16
	for _, l := range p.Stack {
		if v, ok := l.Fields.(*scenario.VLANFields); ok {
			out = append(out, v.VID)
		}
	}
	return out
}

// dirFlow 造一条带方向化 VID 的 flow:一层或多层 vlan + 上下行各一条消息。
// close: none 让包序列只含握手(3)+ 上行消息(数据 + 对端 ACK)+ 下行消息(数据 + 对端 ACK)。
func dirVLANFlow(vlans ...*scenario.VLANFields) scenario.FlowSpec {
	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
	}
	for _, v := range vlans {
		stack = append(stack, scenario.Layer{Type: "vlan", Fields: v})
	}
	stack = append(stack,
		scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
		scenario.Layer{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
	)
	return scenario.FlowSpec{
		Name:  "dir-vlan",
		Stack: stack,
		Messages: []scenario.Message{
			{From: "src", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "up"}}}},
			{From: "dst", Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "down"}}}},
		},
	}
}

// isUplink 判定一个展开包是 src→dst(上行)方向:以太源 MAC 等于模板 src 即上行。
func isUplink(p scenario.Packet) bool {
	for _, l := range p.Stack {
		if e, ok := l.Fields.(*scenario.EthFields); ok {
			return e.Src == "00:00:00:00:00:01"
		}
	}
	return false
}

// TestFlowVLANDirectionalVID 钉住 emit 的方向化 VID 分支:每个展开包(握手/数据/ACK)
// 按自身方向取 src_vid 或 dst_vid,该向缺省则整层摘除。三类需求各一个子用例。
func TestFlowVLANDirectionalVID(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	cases := []struct {
		name    string
		vlans   []*scenario.VLANFields
		wantUp  []uint16 // 上行包的 VID 序列(外→内);nil = 该向无 vlan 层
		wantDwn []uint16
	}{
		{
			name:    "上下行不同 VID",
			vlans:   []*scenario.VLANFields{{SrcVID: u(300), DstVID: u(400)}},
			wantUp:  []uint16{300},
			wantDwn: []uint16{400},
		},
		{
			name:    "上行带、下行不带",
			vlans:   []*scenario.VLANFields{{SrcVID: u(100)}},
			wantUp:  []uint16{100},
			wantDwn: nil,
		},
		{
			name:    "下行带、上行不带",
			vlans:   []*scenario.VLANFields{{DstVID: u(100)}},
			wantUp:  nil,
			wantDwn: []uint16{100},
		},
		{
			name:    "上行双层 QinQ、下行单层",
			vlans:   []*scenario.VLANFields{{SrcVID: u(100), DstVID: u(500)}, {SrcVID: u(200)}},
			wantUp:  []uint16{100, 200},
			wantDwn: []uint16{500},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := dirVLANFlow(tc.vlans...)
			if err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{f}}); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
			if err != nil {
				t.Fatalf("expand: %v", err)
			}
			var ups, downs int
			for i, p := range pkts {
				want := tc.wantDwn
				dir := "下行"
				if isUplink(p.Packet) {
					want, dir = tc.wantUp, "上行"
					ups++
				} else {
					downs++
				}
				if got := vlanVIDs(p.Packet); !slices.Equal(got, want) {
					t.Errorf("包%d(%s)VID 序列=%v,期望 %v", i, dir, got, want)
				}
			}
			// 两向都要有包,否则上面的断言可能因方向缺席而空转。
			if ups == 0 || downs == 0 {
				t.Fatalf("展开包方向覆盖不全:上行 %d / 下行 %d", ups, downs)
			}
		})
	}
}

// TestFlowVLANDirectionalKeepsSharedFields:pri/dei/type 与方向 VID 共存时两向共用
// (v1 不做方向化 PCP/DEI/TPID),且模板 Fields 不被回写(展开两向后模板仍是原值)。
func TestFlowVLANDirectionalKeepsSharedFields(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	pri, dei := uint8(5), true
	tpid := scenario.Hex(0x88a8)
	tmpl := &scenario.VLANFields{SrcVID: u(300), DstVID: u(400), Pri: &pri, DEI: &dei, Type: &tpid}
	f := dirVLANFlow(tmpl)
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for i, p := range pkts {
		for _, l := range p.Stack {
			v, ok := l.Fields.(*scenario.VLANFields)
			if !ok {
				continue
			}
			if v.Pri == nil || *v.Pri != 5 || v.DEI == nil || !*v.DEI || v.Type == nil || *v.Type != tpid {
				t.Errorf("包%d vlan 共用字段丢失: pri=%v dei=%v type=%v", i, v.Pri, v.DEI, v.Type)
			}
			if v.SrcVID != nil || v.DstVID != nil {
				t.Errorf("包%d 展开后仍带方向字段(builder 只认 vid): src=%v dst=%v", i, v.SrcVID, v.DstVID)
			}
		}
	}
	// 模板未被回写:方向字段与 VID 零值原样保留,重复展开结果一致。
	if tmpl.VID != 0 || tmpl.SrcVID == nil || *tmpl.SrcVID != 300 || tmpl.DstVID == nil || *tmpl.DstVID != 400 {
		t.Errorf("模板被回写: vid=%d src=%v dst=%v", tmpl.VID, tmpl.SrcVID, tmpl.DstVID)
	}
}

// TestFlowParseStackInvalidNoPanic:非法 flow.stack 直接进 flow.Expand(绕过
// scenario.Validate 的程序化调用路径)须报错而非 panic。钉住 parseFlowStack 的
// template 坐标系不变式:transportIdx 由「stack 下标 - 1」换算改为循环内记录,
// 双会话层等越界场景不再触发 index out of range。
func TestFlowParseStackInvalidNoPanic(t *testing.T) {
	eth := func() scenario.Layer {
		return scenario.Layer{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}}
	}
	ip := func() scenario.Layer {
		return scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}}
	}
	tcp := func(port uint16) scenario.Layer {
		return scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: port, DPort: 80}}
	}
	udp := func(port uint16) scenario.Layer {
		return scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: port, DPort: 53}}
	}
	cases := []struct {
		name string
		f    scenario.FlowSpec
		want string
	}{
		{
			name: "双会话层(tcp_session 后跟 udp_session)",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(), tcp(1111),
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
				{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
			}},
			want: "不可同时出现",
		},
		{
			name: "双会话层(udp_session 后跟 tcp_session)",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(), udp(1111),
				{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			}},
			want: "不可同时出现",
		},
		{
			name: "会话层无前邻传输层",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(),
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			}},
			want: "前一层须为",
		},
		{
			name: "会话层与传输层不匹配(udp_session 前是 tcp)",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(), tcp(1111),
				{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
			}},
			want: "前一层须为 udp",
		},
		{
			name: "无任何传输层",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(),
			}},
			want: "需要 tcp 层",
		},
		{
			name: "仅 outer udp 残栈且无会话层(旧代码会把隧道外层误当会话传输层)",
			f: scenario.FlowSpec{Stack: []scenario.Layer{
				eth(), ip(), udp(4789),
			}},
			want: "需要 tcp 层",
		},
	}
	msgs := []scenario.Message{{
		From:  "src",
		Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}}},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			f.Messages = msgs
			_, _, _, err := flow.Expand(f, time.Time{}, nil) // 直接调用,不经 Validate
			if err == nil {
				t.Fatalf("Expand() 期望报错(含 %q),得到 nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Expand() error=%v,期望含 %q", err, tc.want)
			}
		})
	}
}
