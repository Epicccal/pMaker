package flow_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

var update = flag.Bool("update", false, "regenerate golden pcap files")

// genFlow 跑完整链路:load -> flow.Expand -> builder.Build -> writer,返回 pcap 字节。
func genFlow(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, f := range s.Flows {
		fp, err := flow.Expand(f)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		s.Packets = append(s.Packets, fp...)
	}
	pkts, err := builder.Build(s)
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

// TestFlowGolden 逐字节比对 golden(确定性输出);首次或改动后用 -update 重生。
func TestFlowGolden(t *testing.T) {
	got := genFlow(t, "../../examples/http_get.yaml")
	golden := filepath.Join("testdata", "http_get.pcap")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("读取 golden 失败(首次请加 -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("与 golden 不一致(%d vs %d 字节)", len(got), len(want))
	}
}

// TestFlowShape 校验握手/挥手标志、包数、SYN 携带 MSS option、应用层字节。
func TestFlowShape(t *testing.T) {
	data := genFlow(t, "../../examples/http_get.yaml")
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
		Client: scenario.Endpoint{MAC: "00:00:00:00:00:01", IP: "10.0.0.1", Port: 1111},
		Server: scenario.Endpoint{MAC: "00:00:00:00:00:02", IP: "10.0.0.2", Port: 80},
		TCP:    scenario.FlowTCP{ClientISN: 1000, ServerISN: 5000, MSS: &mss},
		Open:   "handshake",
		Close:  "none",
		Messages: []scenario.Message{{
			From:    "client",
			RawHex:  hex.EncodeToString(make([]byte, 20)), // 20 字节,mss=8 → 8/8/4 三段
			Segment: &scenario.Segment{MSS: 8},
		}},
	}
	pkts, err := flow.Expand(f)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	// 收集 client 侧带 payload 的数据段(PSH),断言 seq = 1001, 1009, 1017
	var seqs []uint32
	for _, p := range pkts {
		tc := tcpOf(p)
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

// TestFlowCloseRST 校验 close:rst 由 server 单包中断,不再生成 FIN 挥手。
func TestFlowCloseRST(t *testing.T) {
	f := scenario.FlowSpec{
		Client: scenario.Endpoint{MAC: "00:00:00:00:00:01", IP: "10.0.0.1", Port: 1111},
		Server: scenario.Endpoint{MAC: "00:00:00:00:00:02", IP: "10.0.0.2", Port: 80},
		TCP:    scenario.FlowTCP{ClientISN: 1000, ServerISN: 5000},
		Open:   "handshake",
		Close:  "rst",
		Messages: []scenario.Message{{
			From:   "client",
			RawHex: "abcd",
		}},
	}
	pkts, err := flow.Expand(f)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(pkts) != 6 { // 握手3 + 数据1 + ACK1 + RST1
		t.Fatalf("期望 6 个包,得到 %d", len(pkts))
	}
	last := tcpOf(pkts[len(pkts)-1])
	if last == nil || !contains(last.Flags, "RST") || !contains(last.Flags, "ACK") {
		t.Fatalf("最后一个包应为 RST,ACK,得到 %#v", last)
	}
	for i, p := range pkts {
		if tc := tcpOf(p); tc != nil && contains(tc.Flags, "FIN") {
			t.Fatalf("close:rst 不应生成 FIN,但包%d 含 FIN", i)
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
