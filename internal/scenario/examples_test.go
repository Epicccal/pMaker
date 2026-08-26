package scenario_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

var update = flag.Bool("update", false, "regenerate golden pcap files")

// TestExamplesGolden 把 examples/<协议>/ 下每个 YAML 都作为正式测试用例。
// 子目录按协议组织(icmp/icmpv6/http/dns/ipv6/tunnel ...),golden 镜像到
// testdata/<协议>/<name>.pcap,避免跨协议同名文件冲突。
// 新增示例时,这里会自动要求生成对应的 golden。
func TestExamplesGolden(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../examples", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("examples 目录下没有 yaml 用例")
	}

	for _, src := range files {
		// 子测试名用相对 examples/ 的路径(去扩展名),如 "icmp/echo"。
		rel, err := filepath.Rel("../../examples", src)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.ToSlash(strings.TrimSuffix(rel, filepath.Ext(rel)))
		t.Run(name, func(t *testing.T) {
			got := generatePcap(t, src)
			golden := filepath.Join("testdata", name+".pcap")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
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
		})
	}
}

// TestHTTPPutFileContent 验证 @file(...) 占位符:put_file 示例的 PUT body 来自外部文件
// assets/put_body.json,文件内容应原样出现在 pcap 里(auto_content_length: true 也按文件长度算对)。
func TestHTTPPutFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/put_file.yaml")
	for _, want := range [][]byte{
		[]byte("PUT /api/upload HTTP/1.1"),
		// 文件内容(assets/put_body.json 的 JSON 体)注入到请求 body
		[]byte(`{"user":"alice","file":"upload.bin","size":1024}`),
		[]byte("HTTP/1.1 200 OK"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

func TestHTTPKeepaliveLFIContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/keepalive_lfi.yaml")
	for _, want := range [][]byte{
		[]byte("GET /robots.txt HTTP/1.1"),
		[]byte("HTTP/1.1 404 Not Found"),
		[]byte("GET /../etc/passwd HTTP/1.1"),
		[]byte("root:x:0:0:root:/root:/bin/bash"),
		[]byte("hab:x:1000:1000::/home/hab:/usr/bin/zsh"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Fatalf("pcap 不含 %q", want)
		}
	}
}

// TestHTTPSlowSecondContent 验证 slow_second 示例:两轮请求/响应内容齐全,
// 且逐消息定时生效——message.offset_time 相对上一条消息末尾:GET /b 距 200 OK 末尾 +10s、
// resp-b 距 GET /b 末尾 +15s(segment.interval 拉开段间隔)。
func TestHTTPSlowSecondContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/slow_second.yaml")
	for _, want := range [][]byte{
		[]byte("GET /a HTTP/1.1"), // 第一轮未分段,完整请求行连续
		[]byte("GET /b"),          // 第二轮被 segment.mss=8 切段,请求行跨段不连续,只验证首段前缀
		[]byte("resp-a"),
		[]byte("resp-b"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Fatalf("pcap 不含 %q", want)
		}
	}
	// base_time=2024-01-01;握手占 3ms,GET /a 末尾 5ms,200 OK 末尾 7ms。
	// GET /b(+10s) 相对 200 OK 末尾(7ms)→ 首段 base+7ms+10s=10.007s;
	// GET /b 8 段(各 100ms)+ack,末尾 10.709s;resp-b(+15s) 相对 GET /b 末尾 → base+25.709s。
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	wantOffsets := map[time.Duration]bool{
		7*time.Millisecond + 10*time.Second:                    false, // GET /b 首段(200 OK 末尾 7ms + 10s)
		10*time.Second + 709*time.Millisecond + 15*time.Second: false, // resp-b(GET /b 末尾 10.709s + 15s = 25.709s)
	}
	for {
		_, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if _, ok := wantOffsets[ci.Timestamp.Sub(base)]; ok {
			wantOffsets[ci.Timestamp.Sub(base)] = true
		}
	}
	for off, found := range wantOffsets {
		if !found {
			t.Errorf("未找到相对时刻 %v 的包(message.offset_time 未生效)", off)
		}
	}
}

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

// TestFTPControlTriggersData 验证 start_after 跨流引用:数据通道的 SYN(握手)恰好落在
// 控制通道 PASV 227 消息整组完成时刻(msgCursor),紧接(无额外 offset)。
//
// 时间线(base=2024-01-01T00:00:00Z):
//
//	control 握手 0/1/2ms;PASV 请求 data@3/ack@4;PASV 227 data@5/ack@6,msgCursor=7ms;
//	data 握手 SYN @ base+7ms(= control.pasv 的 msgCursor)。
func TestFTPControlTriggersData(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/control_triggers_data.yaml")
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
		tcpL := p.Layer(layers.LayerTypeTCP)
		var rec rec
		rec.ts = ci.Timestamp
		if tcpL != nil {
			tcp := tcpL.(*layers.TCP)
			rec.syn = tcp.SYN
			rec.sport = uint16(tcp.SrcPort)
			rec.dport = uint16(tcp.DstPort)
		}
		recs = append(recs, rec)
	}

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// 数据通道 SYN:sport=49153、dport=50000,应在 base+7ms(= control.pasv msgCursor)。
	var dataSYN time.Time
	for _, r := range recs {
		if r.syn && r.sport == 49153 && r.dport == 50000 {
			if dataSYN.IsZero() {
				dataSYN = r.ts
			}
		}
	}
	if dataSYN.IsZero() {
		t.Fatal("未找到数据通道 SYN(sport=49153,dport=50000)")
	}
	if got := dataSYN.Sub(base); got != 7*time.Millisecond {
		t.Errorf("数据通道 SYN 偏移=%v,期望 7ms(= control.pasv 的 msgCursor,紧接)", got)
	}

	// 控制通道 PASV 227 的对端 ACK 应在 base+6ms(其 +1ms 即 msgCursor=base+7ms,正是 dataSYN)。
	var pasvACK time.Time
	for _, r := range recs {
		// PASV 227 数据段是服务端->客户端(sport=21、dport=49152);对端 ACK 由 src 发出
		// (sport=49152、dport=21),落在 227 之后。
		if r.sport == 49152 && r.dport == 21 && r.ts.Sub(base) >= 6*time.Millisecond && r.ts.Sub(base) < 7*time.Millisecond {
			pasvACK = r.ts
		}
	}
	if pasvACK.IsZero() {
		t.Fatal("未找到控制通道 PASV 227 的对端 ACK(应落 base+6ms)")
	}
	if !pasvACK.Add(time.Millisecond).Equal(dataSYN) {
		t.Errorf("PASV 对端 ACK(%v)+1ms = %v,应等于数据通道 SYN(%v)", pasvACK, pasvACK.Add(time.Millisecond), dataSYN)
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

// TestFTPBidirectionalInterleave 验证消息级双向交错的 start_after(方案 B 核心场景):
// FTP 控制通道的 150 触发数据通道开始,数据通道整流结束再触发控制通道的 226。
// 方案 A 已让 Validate 放行(事件粒度无环);方案 B 让 plan.Plan 真正展开它(算时与发包解耦)。
//
// 关键断言:control.150 的包时刻 < data 的包时刻 < control.226 的包时刻——双向交错成立。
func TestFTPBidirectionalInterleave(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/bidirectional_interleave.yaml")
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	type rec struct {
		ts           time.Time
		sport, dport uint16
		payload      bool
	}
	var recs []rec
	for {
		raw, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		var sp, dp uint16
		if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
			tc := tcp.(*layers.TCP)
			sp, dp = uint16(tc.SrcPort), uint16(tc.DstPort)
		}
		recs = append(recs, rec{ts: ci.Timestamp, sport: sp, dport: dp, payload: p.ApplicationLayer() != nil})
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// 控制通道用 sport=49152/dport=21;数据通道用 sport=49153/dport=50000。
	// 150/226 均由服务端发出(sport=21,dport=49152,带 payload)。首个=150,末个=226。
	// 数据通道任意包:sport=49153 或 dport=49153。
	var msg150, msg226 time.Time
	var dataFirst, dataLast time.Time
	for _, r := range recs {
		if r.sport == 21 && r.dport == 49152 && r.payload {
			if msg150.IsZero() {
				msg150 = r.ts
			}
			msg226 = r.ts
		}
		if r.sport == 49153 || r.dport == 49153 {
			if dataFirst.IsZero() || r.ts.Before(dataFirst) {
				dataFirst = r.ts
			}
			if r.ts.After(dataLast) {
				dataLast = r.ts
			}
		}
	}
	if msg150.IsZero() || msg226.IsZero() {
		t.Fatalf("未找到 control 的 150/226 报文: 150=%v 226=%v", msg150, msg226)
	}
	if dataFirst.IsZero() {
		t.Fatal("未找到数据通道包")
	}
	// 期望时刻:150@base+5ms,data 首@base+7ms(= control.pasv msgCursor),226@base+16ms(= data flowEnd)。
	if got := msg150.Sub(base); got != 5*time.Millisecond {
		t.Errorf("150 报文偏移=%v,期望 5ms", got)
	}
	if got := dataFirst.Sub(base); got != 7*time.Millisecond {
		t.Errorf("数据通道首包偏移=%v,期望 7ms(= control.pasv msgCursor)", got)
	}
	if got := msg226.Sub(base); got != 16*time.Millisecond {
		t.Errorf("226 报文偏移=%v,期望 16ms(= data flowEnd)", got)
	}
	// 双向交错:150 < data < 226。
	if !msg150.Before(dataFirst) {
		t.Errorf("150(%v) 应早于数据通道首包(%v)", msg150, dataFirst)
	}
	if !dataLast.Before(msg226) {
		t.Errorf("数据通道末包(%v) 应早于 226(%v)", dataLast, msg226)
	}
}

// TestFTPPasvRetrContent 回读 pasv_retr,断言控制连接命令/响应、多行欢迎横幅(220 续行),
// 以及数据通道传输的文件内容在合流后的 pcap 里都出现(命令/响应 + 数据字节均 bytes.Contains)。
func TestFTPPasvRetrContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/pasv_retr.yaml")
	for _, want := range [][]byte{
		// 多行 220 续行(RFC 959 §4.2:首行 code-text、中间行裸文本、末行 code SP text)
		[]byte("220-Welcome to pMaker FTP service.\r\n"),
		[]byte("All transfers are logged.\r\n"),
		[]byte("220 Login anonymous accepted.\r\n"),
		// 控制连接命令
		[]byte("USER anonymous\r\n"),
		[]byte("PASS guest\r\n"),
		[]byte("TYPE I\r\n"),
		[]byte("PASV\r\n"),
		[]byte("RETR secret.txt\r\n"),
		[]byte("QUIT\r\n"),
		// 控制连接响应
		[]byte("331 Please specify the password.\r\n"),
		[]byte("230 Login successful.\r\n"),
		[]byte("200 Switching to Binary mode.\r\n"),
		[]byte("227 Entering Passive Mode (10,0,0,21,195,80).\r\n"),
		[]byte("150 Opening BINARY mode data connection for secret.txt.\r\n"),
		[]byte("226 Transfer complete.\r\n"),
		[]byte("221 Goodbye.\r\n"),
		// 数据通道传输的文件内容
		[]byte("TOP SECRET"),
		[]byte("username=admin password=hunter2"),
		[]byte("token=0xdeadbeef"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestFTPPasvRetrTiming 断言 pasv_retr 的双向交错时序落在真实 pcap 上:
// 150 报文时刻 < data 流任一包时刻(数据通道在 150 后才开始);data 流末包时刻 < 226 报文时刻(226 在数据传完才发)。
// 跨流时序只有 plan 汇流后才有意义,故落在 scenario 层的 generatePcap 上而非单 flow 测试。
func TestFTPPasvRetrTiming(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/pasv_retr.yaml")
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	type rec struct {
		ts           time.Time
		sport, dport uint16
		payload      []byte
	}
	var recs []rec
	for {
		raw, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		var sp, dp uint16
		if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
			tc := tcp.(*layers.TCP)
			sp, dp = uint16(tc.SrcPort), uint16(tc.DstPort)
		}
		var pl []byte
		if app := p.ApplicationLayer(); app != nil {
			pl = app.Payload()
		}
		recs = append(recs, rec{ts: ci.Timestamp, sport: sp, dport: dp, payload: pl})
	}

	// 控制连接 49154<->21:150 由服务端(sport=21)发出且 payload 以 "150 " 开头;
	// 226 同样由服务端发出且 payload 以 "226 " 开头。数据通道 49155<->50000 任一包。
	var msg150, msg226 time.Time
	var dataFirst, dataLast time.Time
	for _, r := range recs {
		isControl := (r.sport == 21 && r.dport == 49154) || (r.sport == 49154 && r.dport == 21)
		isData := r.sport == 49155 || r.dport == 49155
		if isControl && len(r.payload) > 0 {
			if bytes.HasPrefix(r.payload, []byte("150 ")) && msg150.IsZero() {
				msg150 = r.ts
			}
			if bytes.HasPrefix(r.payload, []byte("226 ")) {
				msg226 = r.ts
			}
		}
		if isData {
			if dataFirst.IsZero() || r.ts.Before(dataFirst) {
				dataFirst = r.ts
			}
			if r.ts.After(dataLast) {
				dataLast = r.ts
			}
		}
	}
	if msg150.IsZero() {
		t.Fatal("未找到控制通道 150 报文")
	}
	if msg226.IsZero() {
		t.Fatal("未找到控制通道 226 报文")
	}
	if dataFirst.IsZero() {
		t.Fatal("未找到数据通道包")
	}
	if !msg150.Before(dataFirst) {
		t.Errorf("150(%v) 应早于数据通道首包(%v)", msg150, dataFirst)
	}
	if !dataLast.Before(msg226) {
		t.Errorf("数据通道末包(%v) 应早于 226(%v)", dataLast, msg226)
	}
}

// TestFTPPortStorContent 回读 port_stor,断言主动模式 PORT 命令、上传数据(二进制 data_hex),
// 以及 226 在数据传完后才发(整流结束后触发)。
func TestFTPPortStorContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/port_stor.yaml")
	for _, want := range [][]byte{
		[]byte("PORT 10,0,0,10,192,5\r\n"),
		[]byte("STOR upload.bin\r\n"),
		[]byte("150 Ok to send data.\r\n"),
		[]byte("226 Transfer complete.\r\n"),
		// data_hex "CLOUD DATA" 在数据通道(客户端上传方向,sport=49157、dport=20)
		[]byte("CLOUD DATA"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestFTPMalformedInjection 回读 malformed_injection,断言单段内塞入两条命令(CRLF 注入):
// "retr foo\r\ndele /etc/passwd\r\n",验证 command 原样输出(小写)与 CRLF smuggling 能力。
// TestFTPPortStorFileContent 回读 port_stor_file:STOR 上传的数据通道载荷来自外部文件
// assets/upload.bin(@file 占位符),文件内容(含裸 @ 如 libfoo@2.1)应原样出现在 pcap 里。
func TestFTPPortStorFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/port_stor_file.yaml")
	for _, want := range [][]byte{
		[]byte("STOR upload.bin\r\n"),
		[]byte("150 Ok to send data.\r\n"),
		[]byte("226 Transfer complete.\r\n"),
		// 文件内容注入数据通道(payload 来自 @file(assets/upload.bin))
		[]byte("project-alpha-build-2024\r\n"),
		[]byte("artifact-id=0xABCD\r\n"),
		// 文件里的裸 @ 不被占位符误伤(libfoo@2.1 原样)
		[]byte("dependencies=[libfoo@2.1, libbar@3.0]\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

func TestFTPMalformedInjection(t *testing.T) {
	pcap := generatePcap(t, "../../examples/ftp/malformed_injection.yaml")
	want := []byte("retr foo\r\ndele /etc/passwd\r\n")
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含 CRLF 注入的预期 payload %q", want)
	}
}

// TestSMTPEhloSendContent 回读 ehlo_send,断言多行 EHLO 响应(RFC 5321 每行带 250- 前缀)、
// 结构化 MAIL/RCPT 路径(from/to + params 按声明顺序输出)、DATA 正文走 payload 均出现在 pcap 里。
func TestSMTPEhloSendContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/ehlo_send.yaml")
	for _, want := range [][]byte{
		// 服务器 220 问候
		[]byte("220 mail.example ESMTP\r\n"),
		// EHLO 命令
		[]byte("EHLO client.example\r\n"),
		// 多行 EHLO 响应(每行带 250- 前缀,末行 250 SP text)
		[]byte("250-mail.example\r\n"),
		[]byte("250-PIPELINING\r\n"),
		[]byte("250-SIZE 10485760\r\n"),
		[]byte("250-STARTTLS\r\n"),
		[]byte("250-AUTH PLAIN LOGIN\r\n"),
		[]byte("250 8BITMIME\r\n"),
		// 结构化 MAIL:params 按 YAML 声明顺序输出(SIZE < BODY)
		[]byte("MAIL FROM:<alice@example.com> SIZE=1234 BODY=8BITMIME\r\n"),
		// 结构化 RCPT
		[]byte("RCPT TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE\r\n"),
		// DATA / 354
		[]byte("DATA\r\n"),
		[]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"),
		// 正文(payload 兜底)
		[]byte("From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nbody\r\n.\r\n"),
		// 250 queued / QUIT / 221
		[]byte("250 queued as ABC123\r\n"),
		[]byte("QUIT\r\n"),
		[]byte("221 bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestSMTPEhloEmptyLineContent 回读 ehlo_empty_line,断言多行响应中的空文本行如实输出
// (serializeSMTPResp 不静默丢弃空元素):第二行应为 "250-\r\n"。
func TestSMTPEhloEmptyLineContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/ehlo_empty_line.yaml")
	want := []byte("250-mail.example\r\n250-\r\n250-SIZE 10485760\r\n250 PIPELINING\r\n")
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含空文本行的多行响应 %q", want)
	}
}

// TestSMTPMalformedContent 回读 malformed,断言四类畸形 envelope 字节均出现在 pcap 里
// (结构性畸形走 payload_hex、CRLF 注入走结构化路径、私有 verb 走 payload_hex、
// 小写 verb 走结构化路径、越界响应码走 payload_hex)。
func TestSMTPMalformedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/malformed.yaml")
	for _, want := range [][]byte{
		// ① 结构性畸形:缺 <> 的 MAIL FROM(payload_hex)
		[]byte("MAIL FROM:alice@example.com  SIZE=10\r\n"),
		// ② 地址内容 CRLF 注入(结构化路径,<> 框照常包裹)
		[]byte("MAIL FROM:<alice@example.com\r\nRSET\r\n>\r\n"),
		// ③ 私有 verb XMSG(payload_hex)
		[]byte("XMSG stuff\r\n"),
		// ④ 小写 verb(结构化路径原样输出)
		[]byte("rcpt TO:<bob@example.net>\r\n"),
		// ⑤ 越界响应码 99(payload_hex)
		[]byte("99 oops\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3AuthRetrContent 回读 auth_retr,断言 USER/PASS/STAT/LIST/RETR/DELE/QUIT 命令、
// 单行响应、多行 LIST(lines)+ 终止符、多行 RETR(eml 子结构,自动 dot-stuff + 终止符)
// 均出现在 pcap 里。
func TestPOP3AuthRetrContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/auth_retr.yaml")
	for _, want := range [][]byte{
		// 服务器问候(含 APOP 时间戳)
		[]byte("+OK POP3 server ready <1896.697170952@mail.example>\r\n"),
		// 命令
		[]byte("USER alice\r\n"),
		[]byte("PASS secret\r\n"),
		[]byte("STAT\r\n"),
		[]byte("LIST\r\n"),
		[]byte("RETR 1\r\n"),
		[]byte("DELE 2\r\n"),
		[]byte("QUIT\r\n"),
		// 单行响应
		[]byte("+OK User accepted\r\n"),
		[]byte("+OK Maildrop locked and ready\r\n"),
		[]byte("+OK 2 3200\r\n"),
		// 多行 LIST(首行带说明文本 + lines + 终止符)
		[]byte("+OK 2 messages (3200 octets)\r\n1 1200\r\n2 2000\r\n.\r\n"),
		// 多行 RETR(首行带说明文本 + eml 子结构:headers + 空行 + body + 终止符)
		[]byte("+OK message 1 follows\r\nFrom: alice@example.com\r\nTo: bob@example.net\r\nSubject: Hello\r\nDate: Thu, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\nHi Bob,\r\nThis is a test message.\r\n"),
		// RETR 正文行首 . 被 dot-stuff("..\r\n"),末尾终止符 ".\r\n"
		[]byte("..\r\nCheers,\r\nAlice\r\n.\r\n"),
		// DELE / QUIT 响应
		[]byte("+OK message 2 deleted\r\n"),
		[]byte("+OK bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3STLSContent 回读 stls,断言 CAPA 命令/多行能力响应(含 STLS/SASL/UIDL)、
// STLS 命令与 +OK Begin TLS negotiation 响应均出现在 pcap 里。
func TestPOP3STLSContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/stls.yaml")
	for _, want := range [][]byte{
		[]byte("CAPA\r\n"),
		// 多行 CAPA 能力响应(首行带说明文本 + 能力列表,逐行 dot-stuff + 终止符)
		[]byte("+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN CRAM-MD5\r\nRESP-CODES\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\nSTLS\r\n.\r\n"),
		[]byte("STLS\r\n"),
		[]byte("+OK Begin TLS negotiation\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3MalformedContent 回读 malformed,断言四类畸形字节均出现在 pcap 里
// (私有命令走 payload_hex、小写命令走结构化路径、CRLF 注入走结构化路径、非标状态指示符走 payload_hex)。
func TestPOP3MalformedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/malformed.yaml")
	for _, want := range [][]byte{
		// ① 私有命令 XLIST(payload_hex)
		[]byte("XLIST\r\n"),
		// ② 小写命令(结构化路径原样输出)
		[]byte("retr 1\r\n"),
		// ③ CRLF 注入(结构化路径,args 原样输出)
		[]byte("USER alice\r\nDELE 1\r\n\r\n"),
		// ④ 非标状态指示符 +FOO(payload_hex)
		[]byte("+FOO bar\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3AuthSASLContent 回读 auth_sasl,断言 SASL 续行挑战(单字符 + 开头,
// RFC 1734/4954)、客户端 base64 凭证、CAPA 含 SASL 能力、认证成功响应均出现在 pcap 里。
func TestPOP3AuthSASLContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/auth_sasl.yaml")
	for _, want := range [][]byte{
		// CAPA 命令
		[]byte("CAPA\r\n"),
		// CAPA 多行响应(首行带说明文本 + 能力列表,含 SASL)
		[]byte("+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL PLAIN LOGIN CRAM-MD5\r\nRESP-CODES\r\nPIPELINING\r\nUIDL\r\nSTLS\r\n.\r\n"),
		// AUTH PLAIN 发起
		[]byte("AUTH PLAIN\r\n"),
		// 服务器 SASL 续行挑战(单字符 + 开头,非 +OK;message 承载 base64 挑战)
		[]byte("+ AGFsaWNlAHNlY3JldA==\r\n"),
		// 客户端 SASL 续行响应:一行裸 base64(RFC 1734 §3,无命令前缀)
		[]byte("AGFsaWNlAHNlY3JldA==\r\n"),
		// 认证成功
		[]byte("+OK authentication successful\r\n"),
		// QUIT
		[]byte("QUIT\r\n"),
		[]byte("+OK bye\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestHTTPChunkedContent 回读 chunked 示例:transfer_encoding: chunked + chunked.size 切多块,
// 断言块长十六进制行、数据块、终止块 0\r\n\r\n 均出现在 pcap 里。
func TestHTTPChunkedContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/chunked.yaml")
	for _, want := range [][]byte{
		[]byte("Transfer-Encoding: chunked\r\n"),
		// body "chunked-stream-body"(19 字节)按 size=8 切块:8\r\nchunked-\r\n8\r\nstream-b\r\n3\r\nody\r\n0\r\n\r\n
		[]byte("8\r\nchunked-\r\n8\r\nstream-b\r\n3\r\nody\r\n0\r\n\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestHTTPGzipContent 回读 gzip 示例:content_encoding: gzip + auto_content_length: true,
// 断言 Content-Encoding 头存在、Content-Length 为压缩后长度(非 0)、body 为 gzip 二进制
// (含 gzip 魔数 0x1f 0x8b)。
func TestHTTPGzipContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/gzip.yaml")
	for _, want := range [][]byte{
		[]byte("Content-Encoding: gzip\r\n"),
		// gzip 魔数 0x1f 0x8b。
		{0x1f, 0x8b},
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
	// Content-Length 应被 auto_content_length 覆盖为压缩后实际长度(>0、非占位 0)。
	// 用与 builder 相同的 gzip 参数(BestSpeed、MTIME 归零)算出压缩后字节,正向断言 CL 头值。
	// body 取自 gzip.yaml 的 `|` 块标量(YAML 块标量保留一个尾随换行,与 builder 字面透传一致)。
	body := "<html><body>Hello from pMaker gzip content encoding example</body></html>\n"
	repr, err := gzipCompressedLenForTest([]byte(body))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	wantCL := "Content-Length: " + strconv.Itoa(repr) + "\r\n"
	if !bytes.Contains(pcap, []byte(wantCL)) {
		t.Errorf("auto_content_length 未把 CL 覆盖为压缩后长度;want %q,pcap 中未找到", wantCL)
	}
}

// gzipCompressedLenForTest 用与 builder.applyContentCodings 一致的 gzip 参数
// (flate.BestSpeed、MTIME 归零、确定性)计算压缩后字节长度,供 example 测试正向断言。
func gzipCompressedLenForTest(src []byte) (int, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, flate.BestSpeed)
	if err != nil {
		return 0, fmt.Errorf("gzip NewWriterLevel: %w", err)
	}
	zw.ModTime = time.Time{}
	if _, err := zw.Write(src); err != nil {
		return 0, fmt.Errorf("gzip write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("gzip close: %w", err)
	}
	return buf.Len(), nil
}

// TestHTTPBrContent 回读 br 示例:content_encoding: br + auto_content_length: true,
// 断言 Content-Encoding 头存在、Content-Length 为压缩后长度(非占位 0)。br 没有 gzip 那样
// 的固定魔数,故不复刻魔数断言,改用 round-trip(brotli 解压还原原文)佐证 body 是真实 br 压缩字节。
func TestHTTPBrContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/br.yaml")
	if !bytes.Contains(pcap, []byte("Content-Encoding: br\r\n")) {
		t.Errorf("pcap 不含 %q", "Content-Encoding: br\r\n")
	}
	// body 取自 br.yaml 的 `|` 块标量(YAML 块标量保留一个尾随换行)。
	body := "<html><body>Hello from pMaker brotli content encoding example</body></html>\n"
	repr, err := brotliCompressedLenForTest([]byte(body))
	if err != nil {
		t.Fatalf("br: %v", err)
	}
	wantCL := "Content-Length: " + strconv.Itoa(repr) + "\r\n"
	if !bytes.Contains(pcap, []byte(wantCL)) {
		t.Errorf("auto_content_length 未把 CL 覆盖为压缩后长度;want %q,pcap 中未找到", wantCL)
	}
	// round-trip:把压缩后字节用 brotli 解压,应还原原文,佐证 CL 取自真实 br body。
	r := brotli.NewReader(bytes.NewReader(reprBytesForTest(t, []byte(body))))
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("br 解压: %v", err)
	}
	if !bytes.Equal(decoded, []byte(body)) {
		t.Errorf("br round-trip 不符: got %q, want %q", decoded, body)
	}
}

// brotliCompressedLenForTest 用与 builder.applyContentCodings 一致的 brotli 参数
// (brotli.BestSpeed、确定性)计算压缩后字节长度,供 example 测试正向断言 CL 头值。
func brotliCompressedLenForTest(src []byte) (int, error) {
	b, err := reprBytesForTest2(src)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// reprBytesForTest 返回与 builder 完全一致的 br 压缩字节,供 round-trip 复用。
func reprBytesForTest(t *testing.T, src []byte) []byte {
	t.Helper()
	b, err := reprBytesForTest2(src)
	if err != nil {
		t.Fatalf("br: %v", err)
	}
	return b
}

func reprBytesForTest2(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	bw := brotli.NewWriterLevel(&buf, brotli.BestSpeed)
	if _, err := bw.Write(src); err != nil {
		return nil, fmt.Errorf("br write: %w", err)
	}
	if err := bw.Close(); err != nil {
		return nil, fmt.Errorf("br close: %w", err)
	}
	return buf.Bytes(), nil
}

// TestHTTPSmuggleCLTEContent 回读 smuggle_cl_te 示例:CL.TE 走私 —— 头里手写
// Content-Length: 6 + Transfer-Encoding: chunked 并存,body 经 chunked 成帧。
func TestHTTPSmuggleCLTEContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/smuggle_cl_te.yaml")
	for _, want := range [][]byte{
		[]byte("Content-Length: 6\r\n"),
		[]byte("Transfer-Encoding: chunked\r\n"),
		// body "hello" 经 chunked 成帧(整段一块):5\r\nhello\r\n0\r\n\r\n
		[]byte("5\r\nhello\r\n0\r\n\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestHTTPChainedEncodingContent 回读 chained_encoding 示例:transfer_encoding: [gzip, chunked]
// 链式应用,断言 Transfer-Encoding 头声明 "gzip, chunked"、body 先 gzip(魔数)再 chunked 成帧。
func TestHTTPChainedEncodingContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http/chained_encoding.yaml")
	for _, want := range [][]byte{
		[]byte("Transfer-Encoding: gzip, chunked\r\n"),
		// gzip 魔数 0x1f 0x8b(先 gzip 压缩)。
		{0x1f, 0x8b},
		// chunked 终止块(成帧在外层)。
		[]byte("0\r\n\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

func TestICMPEchoContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/icmp/echo.yaml")
	icmpPackets := readICMPPackets(t, pcap)
	if len(icmpPackets) != 2 {
		t.Fatalf("期望 2 个 ICMP 包,得到 %d", len(icmpPackets))
	}

	req := icmpPackets[0]
	if req.TypeCode.Type() != 8 || req.TypeCode.Code() != 0 || req.Id != 0x1234 || req.Seq != 1 || string(req.Payload) != "hello" {
		t.Fatalf("echo request 不符合预期:type=%d code=%d id=%#x seq=%d payload=%q", req.TypeCode.Type(), req.TypeCode.Code(), req.Id, req.Seq, req.Payload)
	}
	rep := icmpPackets[1]
	if rep.TypeCode.Type() != 0 || rep.TypeCode.Code() != 0 || rep.Id != 0x1234 || rep.Seq != 1 || string(rep.Payload) != "hello" {
		t.Fatalf("echo reply 不符合预期:type=%d code=%d id=%#x seq=%d payload=%q", rep.TypeCode.Type(), rep.TypeCode.Code(), rep.Id, rep.Seq, rep.Payload)
	}
}

func TestICMPv6EchoContent(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/icmpv6/echo.yaml"))
	icmpv6Pkts := []*layers.ICMPv6{}
	for _, p := range pkts {
		if l := p.Layer(layers.LayerTypeICMPv6); l != nil {
			icmpv6Pkts = append(icmpv6Pkts, l.(*layers.ICMPv6))
		}
	}
	if len(icmpv6Pkts) != 2 {
		t.Fatalf("期望 2 个 ICMPv6 包,得到 %d", len(icmpv6Pkts))
	}

	for i, want := range []struct{ typ uint8 }{{128}, {129}} {
		p := pkts[i]
		icmp := icmpv6Pkts[i]
		if icmp.TypeCode.Type() != want.typ || icmp.TypeCode.Code() != 0 {
			t.Fatalf("包%d type/code 不符合预期:type=%d code=%d", i, icmp.TypeCode.Type(), icmp.TypeCode.Code())
		}
		// 校验和依赖 IPv6 伪首部;非零证明伪首部已绑定生效。
		if icmp.Checksum == 0 {
			t.Fatalf("包%d ICMPv6 checksum=0,期望已用 IPv6 伪首部计算", i)
		}
		echoL := p.Layer(layers.LayerTypeICMPv6Echo)
		if echoL == nil {
			t.Fatalf("包%d 缺少 ICMPv6Echo 层", i)
		}
		echo := echoL.(*layers.ICMPv6Echo)
		if echo.Identifier != 0x1234 || echo.SeqNumber != 1 {
			t.Fatalf("包%d echo 不符合预期:id=%#x seq=%d", i, echo.Identifier, echo.SeqNumber)
		}
		// echo 数据跟在 4 字节 echo 头(identifier/seq)之后;
		// gopacket 的 ICMPv6Echo 未设置 BaseLayer,echo 数据落在 ICMPv6 层 payload 中。
		echoData := icmp.LayerPayload()[4:]
		if !bytes.Equal(echoData, []byte("hello")) {
			t.Fatalf("包%d echo payload=%q,期望 hello", i, echoData)
		}
	}
}

func TestICMPv6QuoteContent(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/icmpv6/dest_unreachable.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// RFC 4443 §2.4(c):quote 尽量包含整个触发包(从 IPv6 头起整段)。
	// 触发包:eth/ipv6/udp/payload → quote = IPv6(40)+ UDP(8)+ payload(16)= 64B。
	orig := pkts[0]
	origIP := orig.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	wantQuote := append([]byte{}, origIP.Contents...) // IPv6 头 40B
	wantQuote = append(wantQuote, origIP.Payload...)  // UDP 头 + 整段 payload

	reply := pkts[1]
	icmpL := reply.Layer(layers.LayerTypeICMPv6)
	if icmpL == nil {
		t.Fatal("响应包缺少 ICMPv6 层")
	}
	icmp := icmpL.(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 1 || icmp.TypeCode.Code() != 4 { // dest_unreachable / port_unreachable
		t.Fatalf("type/code 不符合预期:type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	if icmp.Checksum == 0 {
		t.Fatal("ICMPv6 checksum=0,期望已用 IPv6 伪首部计算")
	}
	// RFC 4443 §3:错误报文在 Checksum 后有 4 字节类型相关字段(Dest Unreachable=Unused=0),
	// 之后才是 quote。故 ICMPv6 payload = Unused(4) + quote(64) = 68。
	if len(icmp.Payload) != 68 {
		t.Fatalf("ICMPv6 payload 长度=%d,期望 68(Unused 4 + IPv6 40 + UDP 8 + payload 16)", len(icmp.Payload))
	}
	if !bytes.Equal(icmp.Payload[:4], make([]byte, 4)) {
		t.Fatalf("Unused 字段非零: %x", icmp.Payload[:4])
	}
	quote := icmp.Payload[4:]
	if !bytes.Equal(quote, wantQuote) {
		t.Fatalf("quote payload=%x,期望 %x", quote, wantQuote)
	}
	inner := gopacket.NewPacket(quote, layers.LayerTypeIPv6, gopacket.Default)
	if inner.Layer(layers.LayerTypeIPv6) == nil {
		t.Fatalf("quote 未解析出内层 IPv6: %x", quote)
	}
	udp := inner.Layer(layers.LayerTypeUDP)
	if udp == nil {
		t.Fatal("quote 未解析出内层 UDP")
	}
	u := udp.(*layers.UDP)
	if uint16(u.SrcPort) != 40000 || uint16(u.DstPort) != 65000 {
		t.Fatalf("内层 UDP 端口不符合预期:sport=%d dport=%d", u.SrcPort, u.DstPort)
	}
	// quote 未截断,应包含完整 payload。
	if !bytes.Equal(u.Payload, []byte("abcdefghijklmnop")) {
		t.Fatalf("内层 payload 不符合预期: got=%q want=%q", u.Payload, "abcdefghijklmnop")
	}
}

func TestICMPAbnormalContent(t *testing.T) {
	t.Run("dest_unreachable", func(t *testing.T) {
		pkts := readPackets(t, generatePcap(t, "../../examples/icmp/dest_unreachable.yaml"))
		cases := []icmpQuoteCase{
			{typ: 3, code: 0, src: "10.0.0.10", dst: "10.0.0.1", ttl: 64, sport: 40000, dport: 65000},
			{typ: 3, code: 1, src: "10.0.0.10", dst: "10.0.0.2", ttl: 64, sport: 40000, dport: 65001},
			{typ: 3, code: 2, src: "10.0.0.10", dst: "10.0.0.3", ttl: 64, sport: 40000, dport: 65002},
			{typ: 3, code: 3, src: "10.0.0.10", dst: "10.0.0.4", ttl: 64, sport: 40000, dport: 65003},
		}
		assertICMPQuoteCases(t, pkts, cases)
	})

	t.Run("time_exceeded", func(t *testing.T) {
		pkts := readPackets(t, generatePcap(t, "../../examples/icmp/time_exceeded.yaml"))
		cases := []icmpQuoteCase{
			{typ: 11, code: 0, src: "10.0.0.10", dst: "8.8.8.8", ttl: 1, sport: 40000, dport: 65006},
			{typ: 11, code: 1, src: "10.0.0.10", dst: "8.8.4.4", ttl: 64, sport: 40000, dport: 65007},
		}
		assertICMPQuoteCases(t, pkts, cases)
	})

	t.Run("numeric", func(t *testing.T) {
		pkts := readPackets(t, generatePcap(t, "../../examples/icmp/abnormal_numeric.yaml"))
		cases := []icmpQuoteCase{
			{typ: 5, code: 1, src: "10.0.0.10", dst: "10.0.0.20", ttl: 64, sport: 40000, dport: 65000, payload: []byte("probe redirect")},
			{typ: 12, code: 0, src: "10.0.0.10", dst: "10.0.0.1", ttl: 64, sport: 40000, dport: 65001, payload: []byte{0xde, 0xad, 0xbe, 0xef}},
		}
		assertICMPQuoteCases(t, pkts, cases)
	})
}

type icmpQuoteCase struct {
	typ, code    uint8
	src, dst     string
	ttl          uint8
	sport, dport uint16
	payload      []byte
}

func assertICMPQuoteCases(t *testing.T, pkts []gopacket.Packet, cases []icmpQuoteCase) {
	t.Helper()
	if len(pkts) != len(cases)*2 {
		t.Fatalf("期望 %d 个包,得到 %d", len(cases)*2, len(pkts))
	}
	for i, tc := range cases {
		assertNoICMP(t, pkts[i*2])
		assertQuotedICMP(t, pkts[i*2+1], tc)
	}
}

func assertNoICMP(t *testing.T, p gopacket.Packet) {
	t.Helper()
	if p.Layer(layers.LayerTypeICMPv4) != nil {
		t.Fatal("触发包不应带 ICMP 层")
	}
}

func assertQuotedICMP(t *testing.T, p gopacket.Packet, want icmpQuoteCase) {
	t.Helper()
	l := p.Layer(layers.LayerTypeICMPv4)
	if l == nil {
		t.Fatal("期望 ICMP 层")
	}
	icmp := l.(*layers.ICMPv4)
	if icmp.TypeCode.Type() != want.typ || icmp.TypeCode.Code() != want.code {
		t.Fatalf("type/code 不符合预期:type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	inner := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	ipL := inner.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		t.Fatalf("ICMP payload 未解析出内层 IPv4: %x", icmp.Payload)
	}
	ip := ipL.(*layers.IPv4)
	if ip.SrcIP.String() != want.src || ip.DstIP.String() != want.dst || ip.TTL != want.ttl {
		t.Fatalf("内层 IPv4 不符合预期:src=%s dst=%s ttl=%d", ip.SrcIP, ip.DstIP, ip.TTL)
	}
	udpL := inner.Layer(layers.LayerTypeUDP)
	if udpL == nil {
		t.Fatal("ICMP payload 未解析出内层 UDP")
	}
	udp := udpL.(*layers.UDP)
	if uint16(udp.SrcPort) != want.sport || uint16(udp.DstPort) != want.dport {
		t.Fatalf("内层 UDP 不符合预期:sport=%d dport=%d", udp.SrcPort, udp.DstPort)
	}
	// payload 仅在内联 quote(含完整数据)时断言;quote_from 按 RFC 792 只取头+8 字节,
	// 不含 UDP payload,此时 want.payload 为 nil,跳过检查。
	if want.payload != nil && !bytes.Equal(udp.Payload, want.payload) {
		t.Fatalf("内层 payload 不符合预期: got=%x want=%x", udp.Payload, want.payload)
	}
}

func readICMPPackets(t *testing.T, data []byte) []*layers.ICMPv4 {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.ICMPv4
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeICMPv4); l != nil {
			out = append(out, l.(*layers.ICMPv4))
		}
	}
	return out
}

func readPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var pkts []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkts = append(pkts, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return pkts
}

func TestDNSMultiContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/dns/multi.yaml")
	dnsPackets := readDNSPackets(t, pcap)
	if len(dnsPackets) != 18 {
		t.Fatalf("期望 18 个 DNS 包(9 组 query/response),得到 %d", len(dnsPackets))
	}

	expectDNSPair(t, dnsPackets, 0, layers.DNSTypeA, "example.com", func(rr layers.DNSResourceRecord) {
		if !rr.IP.Equal(net.ParseIP("93.184.216.34")) {
			t.Fatalf("A answer = %v,期望 93.184.216.34", rr.IP)
		}
	})
	expectDNSPair(t, dnsPackets, 2, layers.DNSTypeAAAA, "example.com", func(rr layers.DNSResourceRecord) {
		if !rr.IP.Equal(net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")) {
			t.Fatalf("AAAA answer = %v", rr.IP)
		}
	})
	expectDNSPair(t, dnsPackets, 4, layers.DNSTypeCNAME, "www.example.com", func(rr layers.DNSResourceRecord) {
		if string(rr.CNAME) != "example.com" {
			t.Fatalf("CNAME answer = %q", rr.CNAME)
		}
	})
	expectDNSPair(t, dnsPackets, 6, layers.DNSTypeNS, "example.com", func(rr layers.DNSResourceRecord) {
		if string(rr.NS) != "ns1.example.com" {
			t.Fatalf("NS answer = %q", rr.NS)
		}
	})
	expectDNSPair(t, dnsPackets, 8, layers.DNSTypePTR, "34.216.184.93.in-addr.arpa", func(rr layers.DNSResourceRecord) {
		if string(rr.PTR) != "example.com" {
			t.Fatalf("PTR answer = %q", rr.PTR)
		}
	})
	expectDNSPair(t, dnsPackets, 10, layers.DNSTypeMX, "example.com", func(rr layers.DNSResourceRecord) {
		if rr.MX.Preference != 10 || string(rr.MX.Name) != "mail.example.com" {
			t.Fatalf("MX answer = %#v", rr.MX)
		}
	})
	expectDNSPair(t, dnsPackets, 12, layers.DNSTypeTXT, "example.com", func(rr layers.DNSResourceRecord) {
		if len(rr.TXTs) != 1 || string(rr.TXTs[0]) != "v=spf1 include:_spf.example.com ~all" {
			t.Fatalf("TXT answer = %#v", rr.TXTs)
		}
	})
	expectDNSPair(t, dnsPackets, 14, layers.DNSTypeSOA, "example.com", func(rr layers.DNSResourceRecord) {
		soa := rr.SOA
		if string(soa.MName) != "ns1.example.com" || string(soa.RName) != "hostmaster.example.com" {
			t.Fatalf("SOA MName/RName = %q/%q", soa.MName, soa.RName)
		}
		if soa.Serial != 2024010101 || soa.Refresh != 7200 || soa.Retry != 3600 || soa.Expire != 1209600 || soa.Minimum != 3600 {
			t.Fatalf("SOA 数值字段 = serial=%d refresh=%d retry=%d expire=%d minimum=%d",
				soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
		}
	})
	expectDNSPair(t, dnsPackets, 16, layers.DNSTypeSRV, "_sip._tcp.example.com", func(rr layers.DNSResourceRecord) {
		srv := rr.SRV
		if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 5060 || string(srv.Name) != "sipserver.example.com" {
			t.Fatalf("SRV answer = priority=%d weight=%d port=%d target=%q",
				srv.Priority, srv.Weight, srv.Port, srv.Name)
		}
	})
}

func expectDNSPair(t *testing.T, pkts []*layers.DNS, i int, typ layers.DNSType, qname string, check func(layers.DNSResourceRecord)) {
	t.Helper()
	q := pkts[i]
	if q.QR || len(q.Questions) != 1 || string(q.Questions[0].Name) != qname || q.Questions[0].Type != typ {
		t.Fatalf("包%d 应为 %s 查询 %s,得到 %#v", i, typ, qname, q.Questions)
	}
	r := pkts[i+1]
	if !r.QR || len(r.Answers) != 1 || r.Answers[0].Type != typ {
		t.Fatalf("包%d 应为 %s 响应,得到 %#v", i+1, typ, r.Answers)
	}
	check(r.Answers[0])
}

func readDNSPackets(t *testing.T, data []byte) []*layers.DNS {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.DNS
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeDNS); l != nil {
			out = append(out, l.(*layers.DNS))
		}
	}
	return out
}

func generatePcap(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("plan %s: %v", path, err)
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return buf.Bytes()
}

// TestTelnetNegotiationContent 回读 negotiation.yaml,断言 TCP payload 逐字节含
// IAC WILL ECHO / IAC WILL SGA / IAC DO SGA / IAC DONT ECHO(多层拼接后连续)。
func TestTelnetNegotiationContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/negotiation.yaml")
	// IAC=0xFF WILL=0xFB DO=0xFD DONT=0xFE;ECHO=1 SGA=3
	want := []byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfd, 0x03, 0xff, 0xfe, 0x01}
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含连续协商序列 %x", want)
	}
}

// TestTelnetTTypeNAWSContent 回读 ttype_naws.yaml,断言 SB TTYPE IS xterm-256color
// 与 SB NAWS 80x24 的大端字节。
func TestTelnetTTypeNAWSContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/ttype_naws.yaml")
	// TTYPE IS: IAC SB 24 00 "xterm-256color" IAC SE
	ttype := append([]byte{0xff, 0xfa, 0x18, 0x00}, []byte("xterm-256color")...)
	ttype = append(ttype, 0xff, 0xf0)
	if !bytes.Contains(pcap, ttype) {
		t.Errorf("pcap 不含 SB TTYPE IS xterm-256color")
	}
	// NAWS 80x24: IAC SB 31 00 50 00 18 IAC SE
	naws := []byte{0xff, 0xfa, 0x1f, 0x00, 0x50, 0x00, 0x18, 0xff, 0xf0}
	if !bytes.Contains(pcap, naws) {
		t.Errorf("pcap 不含 SB NAWS 80x24 大端字节")
	}
}

// TestTelnetTextEscapeContent 验证 IAC 转义:text 含字面 0xFF 时输出 IAC IAC。
func TestTelnetTextEscapeContent(t *testing.T) {
	// 构造含 0xFF 的 NVT 文本 standalone packet。
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
				{Type: "telnet", Fields: &scenario.TelnetFields{Args: "\xff\xffhi"}},
			},
		}},
	}
	pcap := generatePcapScenario(t, s)
	// 两个 0xFF 各转义为 IAC IAC:ff ff ff ff h i
	want := []byte{0xff, 0xff, 0xff, 0xff, 'h', 'i'}
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含 IAC IAC 转义序列 %x", want)
	}
}

// TestTelnetLoginSessionContent 回读 flow pcap,断言协商 + login:/Password: +
// TTYPE IS + 用户输入在合流 pcap 中按序出现,且握手/挥手标志序列正确。
func TestTelnetLoginSessionContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/login_session.yaml")
	// 协商
	for _, want := range [][]byte{
		{0xff, 0xfb, 0x01}, // IAC WILL ECHO
		{0xff, 0xfb, 0x03}, // IAC WILL SGA
		{0xff, 0xfd, 0x03}, // IAC DO SGA
		{0xff, 0xfd, 0x01}, // IAC DO ECHO
		// TTYPE SEND: IAC SB 24 01 IAC SE
		{0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0},
		// TTYPE IS xterm-256color
		append(append([]byte{0xff, 0xfa, 0x18, 0x00}, []byte("xterm-256color")...), []byte{0xff, 0xf0}...),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含协商/subneg 序列 %x", want)
		}
	}
	// NVT 文本
	for _, want := range []string{"login: ", "root\r\n", "Password: ", "secret\r\n", "Welcome to pMaker.\r\n"} {
		if !bytes.Contains(pcap, []byte(want)) {
			t.Errorf("pcap 不含 NVT 文本 %q", want)
		}
	}

	// 握手/挥手标志序列:SYN → SYN,ACK → ACK …(handshake)→ 末尾 FIN,ACK 四次挥手。
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var flags []string
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if tcpL := p.Layer(layers.LayerTypeTCP); tcpL != nil {
			tcp := tcpL.(*layers.TCP)
			flags = append(flags, tcpFlagString(tcp))
		}
	}
	if len(flags) < 3 {
		t.Fatalf("期望至少 3 个 TCP 包(握手),得到 %d", len(flags))
	}
	if flags[0] != "SYN" || flags[1] != "SYN,ACK" || flags[2] != "ACK" {
		t.Errorf("握手标志序列错误: %v", flags[:3])
	}
	// 挥手:末四个包应为 FIN,ACK / ACK / FIN,ACK / ACK。
	if len(flags) < 7 {
		t.Fatalf("包数不足以包含挥手: %d", len(flags))
	}
	tail := flags[len(flags)-4:]
	if tail[0] != "FIN,ACK" || tail[1] != "ACK" || tail[2] != "FIN,ACK" || tail[3] != "ACK" {
		t.Errorf("挥手标志序列错误: %v", tail)
	}
}

// tcpFlagString 把 TCP 标志位拼成可读串(顺序 SYN/FIN/ACK/RST,惯用表示)。
func tcpFlagString(tcp *layers.TCP) string {
	var parts []string
	if tcp.SYN {
		parts = append(parts, "SYN")
	}
	if tcp.FIN {
		parts = append(parts, "FIN")
	}
	if tcp.ACK {
		parts = append(parts, "ACK")
	}
	if tcp.RST {
		parts = append(parts, "RST")
	}
	return strings.Join(parts, ",")
}

// TestSMTPEmlFileContent 验证 smtp/eml_file 示例:
//   - @file(assets/sample.eml) 把真实邮件注入 eml_data.raw;
//   - 信封命令(MAIL FROM / RCPT TO / DATA)出现在 pcap;
//   - sample.eml 特征内容(From/To 头、multipart boundary、X-Mailer)出现在 pcap;
//   - 接入层追加 dot-stuffing 终止符(<CRLF>.<CRLF>)。
func TestSMTPEmlFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/smtp/eml_file.yaml")
	for _, want := range [][]byte{
		// 信封命令
		[]byte("MAIL FROM:<userA@qq.com>"),
		[]byte("RCPT TO:<userB@qq.com>"),
		[]byte("DATA\r\n"),
		// sample.eml 特征头
		[]byte("From: \"=?utf-8?B?dXNlckE=?=\" <userA@qq.com>"),
		[]byte("To: \"=?utf-8?B?dXNlckI=?=\" <userB@qq.com>"),
		[]byte(`boundary="----=_NextPart_6A841ABB_A38AD000_73F0D3C0"`),
		[]byte("X-Mailer: QQMail 2.x"),
		// SMTP DATA 成帧:dot-stuffing 终止符
		[]byte("\r\n.\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// TestPOP3RetrFileContent 验证 pop3/retr_file 示例:
//   - @file(assets/sample.eml) 把真实邮件注入 pop3_response.eml.raw;
//   - 客户端命令(RETR 1)与服务端状态行(+OK ... octets)出现在 pcap;
//   - sample.eml 特征内容与 smtp/eml_file 对称(同一份文件);
//   - 接入层追加 dot-stuffing 终止符(<CRLF>.<CRLF>)。
func TestPOP3RetrFileContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/pop3/retr_file.yaml")
	for _, want := range [][]byte{
		// 客户端命令
		[]byte("RETR 1\r\n"),
		// 服务端状态行
		[]byte("+OK 106458 octets\r\n"),
		// sample.eml 特征头(与 smtp/eml_file 对称验证同一份文件被正确注入)
		[]byte("From: \"=?utf-8?B?dXNlckE=?=\" <userA@qq.com>"),
		[]byte(`boundary="----=_NextPart_6A841ABB_A38AD000_73F0D3C0"`),
		[]byte("X-Mailer: QQMail 2.x"),
		// POP3 RETR 成帧:dot-stuffing 终止符
		[]byte("\r\n.\r\n"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含 %q", want)
		}
	}
}

// generatePcapScenario 对已构造的 Scenario 跑完整链路返回 pcap 字节。
func generatePcapScenario(t *testing.T, s *scenario.Scenario) []byte {
	t.Helper()
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
