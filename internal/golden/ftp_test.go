package golden_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

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
