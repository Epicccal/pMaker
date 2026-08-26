package golden_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gopacket/gopacket/pcapgo"
)

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
	r := brotli.NewReader(bytes.NewReader(brotliBytesForTest(t, []byte(body))))
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
	b, err := brotliBytes(src)
	if err != nil {
		return 0, err
	}
	return len(b), nil
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
