package builder_test

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 HTTP 内容编码(CE)/传输编码(TE)成帧与自动 Content-Length 的 builder 级
// 单测(对应 http_coding.go 的纯函数 + serializeHTTPReq/Resp 端到端)。
//
// 覆盖点:
//   - applyContentCodings / applyTransferCodings / compressCoding / chunkedFrame 的函数边界;
//   - 确定性:三值(gzip/deflate/deflate_raw)连续两次构建逐字节相同;
//   - 链式:content_encoding: [deflate, gzip] == gzip(deflate(body));[gzip, chunked] == chunked(gzip(body));
//   - chunked: size 切多块块长十六进制;缺省/空/size=0 三者整段一块;始终追加 0\r\n\r\n;空 body 仅终止块;
//   - applyAutoContentLength: auto=true 覆盖已有 CL(位置不变)/ 末尾追加;false 不动 Header;
//   - 函数边界:applyContentCodings 遇 chunked 报错;applyTransferCodings 遇未知 coding 报错。

func mustReqBytes(t *testing.T, f *scenario.HTTPReqFields) []byte {
	t.Helper()
	b, err := builder.PayloadBytes(scenario.Layer{Type: "http_request", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	return b
}

func mustRespBytes(t *testing.T, f *scenario.HTTPRespFields) []byte {
	t.Helper()
	b, err := builder.PayloadBytes(scenario.Layer{Type: "http_response", Fields: f})
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	return b
}

// compressDeterministic 表驱动:同一 body 两次压缩应逐字节相同。
func TestCompressCoding_Deterministic(t *testing.T) {
	body := []byte("Hello from pMaker! The quick brown fox jumps over the lazy dog. 1234567890")
	for _, name := range []string{scenario.CodingGzip, scenario.CodingDeflate, scenario.CodingDeflateRaw, scenario.CodingBr} {
		c1, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{name})
		if err != nil {
			t.Fatalf("%s 第一次: %v", name, err)
		}
		c2, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{name})
		if err != nil {
			t.Fatalf("%s 第二次: %v", name, err)
		}
		if !bytes.Equal(c1, c2) {
			t.Errorf("%s 两次压缩结果不一致(确定性失败): len=%d vs %d", name, len(c1), len(c2))
		}
		// 压缩后长度应与原文不同(否则没真压缩)。
		if len(c1) == len(body) {
			t.Logf("警告:%s 压缩后长度与原文相同(len=%d),可能未真压缩", name, len(c1))
		}
	}
}

func TestApplyContentCodings_Empty(t *testing.T) {
	body := []byte("hello")
	got, err := builder.ApplyContentCodingsForTest(body, nil)
	if err != nil {
		t.Fatalf("空 CE: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("空 CE 应原样返回, got %q", got)
	}
	// IsNone(含 NONE)也应原样返回。
	got, err = builder.ApplyContentCodingsForTest(body, scenario.CodingList{"NONE"})
	if err != nil {
		t.Fatalf("CE=[NONE]: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("CE=[NONE] 应原样返回, got %q", got)
	}
}

func TestApplyContentCodings_ChunkedRejected(t *testing.T) {
	_, err := builder.ApplyContentCodingsForTest([]byte("x"), scenario.CodingList{"CHUNKED"})
	if err == nil {
		t.Error("CE 含 chunked 应报错(chunked 是传输编码)")
	}
}

func TestApplyTransferCodings_UnknownRejected(t *testing.T) {
	_, err := builder.ApplyTransferCodingsForTest([]byte("x"), scenario.CodingList{"UNKNOWN"}, scenario.ChunkedOptions{})
	if err == nil {
		t.Error("TE 含未知 coding 应报错")
	}
}

// br(Brotli)内容编码:round-trip(压缩→解压还原)+ 确定性(两次压缩逐字节相同)。
func TestCompressCoding_Brotli(t *testing.T) {
	body := []byte("Hello from pMaker brotli! The quick brown fox jumps over the lazy dog. 1234567890")

	// 确定性:两次压缩逐字节相同。
	c1, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{scenario.CodingBr})
	if err != nil {
		t.Fatalf("br 第一次: %v", err)
	}
	c2, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{scenario.CodingBr})
	if err != nil {
		t.Fatalf("br 第二次: %v", err)
	}
	if !bytes.Equal(c1, c2) {
		t.Errorf("br 两次压缩结果不一致(确定性失败): len=%d vs %d", len(c1), len(c2))
	}

	// round-trip:用 andybalholm/brotli.NewReader 解压还原原文。
	r := brotli.NewReader(bytes.NewReader(c1))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("br 解压: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("br round-trip 不符: got %q, want %q", got, body)
	}
}

// 链式:content_encoding: [deflate, gzip] == gzip(deflate(body))。
func TestApplyContentCodings_Chained(t *testing.T) {
	body := []byte("chained encoding test: deflate then gzip, RFC 9110 §8.4 按序应用")
	got, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{"DEFLATE", "GZIP"})
	if err != nil {
		t.Fatalf("链式 CE: %v", err)
	}
	// 先 deflate 再 gzip = gzip(deflate(body))
	deflated, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{"DEFLATE"})
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	expected, err := builder.ApplyContentCodingsForTest(deflated, scenario.CodingList{"GZIP"})
	if err != nil {
		t.Fatalf("gzip(deflate): %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("链式 [deflate, gzip] != gzip(deflate(body))")
	}
}

// 链式:transfer_encoding: [gzip, chunked] == chunked(gzip(body))。
func TestApplyTransferCodings_ChainedGzipChunked(t *testing.T) {
	body := []byte("gzip then chunked: 先压缩再分块成帧,RFC 9112 §7.1")
	got, err := builder.ApplyTransferCodingsForTest(body, scenario.CodingList{"GZIP", "CHUNKED"}, scenario.ChunkedOptions{})
	if err != nil {
		t.Fatalf("链式 TE: %v", err)
	}
	gzipped, err := builder.ApplyContentCodingsForTest(body, scenario.CodingList{"GZIP"})
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	expected := builder.ChunkedFrameForTest(gzipped, 0)
	if !bytes.Equal(got, expected) {
		t.Errorf("链式 [gzip, chunked] != chunkedFrame(gzip(body))")
	}
}

// 异常栈:transfer_encoding: [chunked, gzip] —— chunked 非末位,RFC 9112 非常规顺序
// (属告警路径,evasion 测试面)。builder 不判合规性,只机械按列表顺序 fold:
// [chunked, gzip] = gzip(chunkedFrame(body))(先 chunked 成帧,再 gzip 压缩成帧后的字节)。
func TestApplyTransferCodings_ChainedChunkedGzip(t *testing.T) {
	body := []byte("chunked then gzip: 先分块成帧再压缩,异常编码栈 evasion,RFC 9112 §7.1")
	got, err := builder.ApplyTransferCodingsForTest(body, scenario.CodingList{"CHUNKED", "GZIP"}, scenario.ChunkedOptions{})
	if err != nil {
		t.Fatalf("异常栈 TE: %v", err)
	}
	// 先 chunked 成帧。
	framed := builder.ChunkedFrameForTest(body, 0)
	// 再 gzip 压缩成帧后的字节。
	expected, err := builder.ApplyContentCodingsForTest(framed, scenario.CodingList{"GZIP"})
	if err != nil {
		t.Fatalf("gzip(chunkedFrame): %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("异常栈 [chunked, gzip] != gzip(chunkedFrame(body))")
	}
}

// 异常栈:transfer_encoding: [chunked, chunked] —— 双 chunked(RFC 9112 §7.1 异常编码栈,
// IDS 绕过特征,告警路径)。builder 机械按序 fold:[chunked, chunked] = chunkedFrame(chunkedFrame(body))
// (对已分帧的字节再分一次块;两次成帧共用同一 ChunkedOptions.Size)。
func TestApplyTransferCodings_DoubleChunked(t *testing.T) {
	body := []byte("double chunked: 对已分帧字节再分块,异常编码栈 IDS 绕过特征")
	size := 4
	got, err := builder.ApplyTransferCodingsForTest(body, scenario.CodingList{"CHUNKED", "CHUNKED"}, scenario.ChunkedOptions{Size: size})
	if err != nil {
		t.Fatalf("双 chunked TE: %v", err)
	}
	// 两次 chunked 成帧共用 opts.Size(builder 对列表中每个 CHUNKED 都用同一 Size)。
	inner := builder.ChunkedFrameForTest(body, size)
	expected := builder.ChunkedFrameForTest(inner, size)
	if !bytes.Equal(got, expected) {
		t.Errorf("双 chunked [chunked, chunked] != chunkedFrame(chunkedFrame(body))")
	}
}

func TestChunkedFrame_WholeOneChunk(t *testing.T) {
	// size<=0:整段一块。
	body := []byte("hello world")
	got := builder.ChunkedFrameForTest(body, 0)
	want := "b\r\nhello world\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("整段一块 got %q, want %q", got, want)
	}
}

func TestChunkedFrame_MultiChunk(t *testing.T) {
	// size=4:切多块,块长十六进制。
	body := []byte("hello world!") // 12 字节
	got := builder.ChunkedFrameForTest(body, 4)
	want := "4\r\nhell\r\n4\r\no wo\r\n4\r\nrld!\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("切多块 got %q, want %q", got, want)
	}
}

func TestChunkedFrame_EmptyBody(t *testing.T) {
	// 空 body:仅终止块。
	got := builder.ChunkedFrameForTest(nil, 0)
	want := "0\r\n\r\n"
	if string(got) != want {
		t.Errorf("空 body got %q, want %q", got, want)
	}
}

func TestChunkedFrame_DefaultSizeWholeChunk(t *testing.T) {
	// size==0:整段一块(契约行为)。size<0 是 scenario 校验硬错,不应到达 builder,
	// 故此处只测合法的 size==0,不把非法负数路径当作等价语义固化。
	body := []byte("xyz")
	got := builder.ChunkedFrameForTest(body, 0)
	want := "3\r\nxyz\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("size=0 整段一块 got %q, want %q", got, want)
	}
}

func TestChunkedFrame_SizeLargerThanBody(t *testing.T) {
	// size 大于 body 长度:单块,块长 == body 实际长度(不按 size 截断出空块)。
	body := []byte("short") // 5 字节
	got := builder.ChunkedFrameForTest(body, 100)
	want := "5\r\nshort\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("size>len got %q, want %q(应为单块,块长=body 长度)", got, want)
	}
}

func TestChunkedFrame_NonDivisibleRemainder(t *testing.T) {
	// size 不能整除:最后一块为余数,块长反映实际剩余字节。
	body := []byte("hello world!") // 12 字节,size=5 -> 5+5+2
	got := builder.ChunkedFrameForTest(body, 5)
	want := "5\r\nhello\r\n5\r\n worl\r\n2\r\nd!\r\n0\r\n\r\n"
	if string(got) != want {
		t.Errorf("非整除余数 got %q, want %q(最后一块应为 2 字节)", got, want)
	}
}

func TestApplyAutoContentLength_Off(t *testing.T) {
	h := scenario.HeaderMap{{Key: "Content-Length", Value: "999"}}
	got := builder.ApplyAutoContentLengthForTest(h, false, 42)
	if !bytes.Equal([]byte(got[0].Value), []byte("999")) {
		t.Errorf("auto=false 不动 Header, got %v", got[0].Value)
	}
}

func TestApplyAutoContentLength_Overwrite(t *testing.T) {
	h := scenario.HeaderMap{
		{Key: "Content-Type", Value: "text/plain"},
		{Key: "Content-Length", Value: "999"},
		{Key: "X-Foo", Value: "bar"},
	}
	got := builder.ApplyAutoContentLengthForTest(h, true, 42)
	// 位置不变,值被覆盖为 42。
	if len(got) != 3 {
		t.Fatalf("条目数应不变, got %d", len(got))
	}
	if got[1].Key != "Content-Length" || got[1].Value != "42" {
		t.Errorf("CL 应在原位置被覆盖为 42, got %v", got[1])
	}
}

func TestApplyAutoContentLength_Append(t *testing.T) {
	h := scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}}
	got := builder.ApplyAutoContentLengthForTest(h, true, 7)
	if len(got) != 2 {
		t.Fatalf("应末尾追加 CL, got %d", len(got))
	}
	last := got[len(got)-1]
	if last.Key != "Content-Length" || last.Value != "7" {
		t.Errorf("末尾追加 CL=7, got %v", last)
	}
}

// 端到端:auto=true + gzip -> CL == 压缩后长度;CE/TE 顺序固定。
func TestSerializeHTTPResp_AutoCLWithGzip(t *testing.T) {
	body := "Hello from pMaker gzip content length test"
	f := &scenario.HTTPRespFields{
		Status:            200,
		AutoContentLength: true,
		ContentEncoding:   scenario.CodingList{"GZIP"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Encoding", Value: "gzip"},
			{Key: "Content-Length", Value: "0"},
		},
		Body: body,
	}
	got := mustRespBytes(t, f)
	// 计算 gzip 后长度(CE 之后、TE 之前)。
	repr, err := builder.ApplyContentCodingsForTest([]byte(body), scenario.CodingList{"GZIP"})
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	wantCL := "Content-Length: " + strconv.Itoa(len(repr))
	if !bytes.Contains(got, []byte(wantCL)) {
		t.Errorf("CL 应为压缩后长度 %s, got %q", wantCL, got)
	}
}

// 端到端:auto=true + deflate/deflate_raw -> CL == 各自压缩后长度。
// 覆盖 httpPayload 管线对非 gzip 内容编码的端到端正确性(此前仅 gzip 端到端,
// deflate/deflate_raw 只在 TestCompressCoding_Deterministic 测了纯函数)。
func TestSerializeHTTPResp_AutoCLWithDeflateCodings(t *testing.T) {
	body := "deflate and deflate_raw end-to-end content length test payload"
	for _, ce := range []scenario.CodingList{
		{scenario.CodingDeflate},
		{scenario.CodingDeflateRaw},
	} {
		f := &scenario.HTTPRespFields{
			Status:            200,
			AutoContentLength: true,
			ContentEncoding:   ce,
			Headers: scenario.HeaderMap{
				{Key: "Content-Length", Value: "0"},
			},
			Body: body,
		}
		got := mustRespBytes(t, f)
		repr, err := builder.ApplyContentCodingsForTest([]byte(body), ce)
		if err != nil {
			t.Fatalf("%v: %v", ce, err)
		}
		wantCL := "Content-Length: " + strconv.Itoa(len(repr))
		if !bytes.Contains(got, []byte(wantCL)) {
			t.Errorf("%v: CL 应为压缩后长度 %s, got %q", ce, wantCL, got)
		}
	}
}

// 端到端:auto=true + br(Brotli)-> CL == 压缩后长度。
// 覆盖 httpPayload 管线对 br 内容编码的端到端正确性:占位 Content-Length: 0 应被
// applyAutoContentLength 原位覆盖为 brotli 压缩后字节长度(CE 之后、TE 之前的基准)。
// br 此前仅在 TestCompressCoding_Brotli 测了纯函数(确定性 + round-trip),未覆盖
// auto_content_length 的端到端路径。
func TestSerializeHTTPResp_AutoCLWithBr(t *testing.T) {
	body := "Hello from pMaker brotli content length end-to-end test payload"
	f := &scenario.HTTPRespFields{
		Status:            200,
		AutoContentLength: true,
		ContentEncoding:   scenario.CodingList{scenario.CodingBr},
		Headers: scenario.HeaderMap{
			{Key: "Content-Length", Value: "0"}, // 占位,应被原位覆盖
		},
		Body: body,
	}
	got := mustRespBytes(t, f)
	repr, err := builder.ApplyContentCodingsForTest([]byte(body), scenario.CodingList{scenario.CodingBr})
	if err != nil {
		t.Fatalf("br: %v", err)
	}
	wantCL := "Content-Length: " + strconv.Itoa(len(repr))
	if !bytes.Contains(got, []byte(wantCL)) {
		t.Errorf("br: CL 应为压缩后长度 %s, got %q", wantCL, got)
	}
	// round-trip 兜底:压缩后字节能解压回原文,证明 autoCL 取的是真实 br body 的长度。
	r := brotli.NewReader(bytes.NewReader(repr))
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("br 解压: %v", err)
	}
	if !bytes.Equal(decoded, []byte(body)) {
		t.Errorf("br round-trip 不符: got %q, want %q", decoded, body)
	}
}

// 端到端:chunked + size 切多块。
func TestSerializeHTTPResp_Chunked(t *testing.T) {
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Chunked:          &scenario.ChunkedOptions{Size: 4},
		Headers: scenario.HeaderMap{
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
		Body: "hello world!",
	}
	got := mustRespBytes(t, f)
	wantBody := "4\r\nhell\r\n4\r\no wo\r\n4\r\nrld!\r\n0\r\n\r\n"
	if !bytes.Contains(got, []byte(wantBody)) {
		t.Errorf("chunked 切块不符, got %q", got)
	}
}

// 端到端:chunked 时空 body 合规输出仅终止块。
func TestSerializeHTTPResp_ChunkedEmptyBody(t *testing.T) {
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Transfer-Encoding", Value: "chunked"}},
		Body:             "",
	}
	got := mustRespBytes(t, f)
	if !bytes.Contains(got, []byte("\r\n0\r\n\r\n")) {
		t.Errorf("空 body chunked 应含终止块, got %q", got)
	}
}

// 端到端:auto=true + TE 非空会触发 scenario 校验硬错,此处验证 builder 侧不应产出 CL
// (httpPayload 在 autoCL && TE 非空时走不到自动 CL——但校验已拦截,这里测合法路径:
// auto=false + chunked + 手写 CL 走私用例,CL 原样保留)。
func TestSerializeHTTPReq_SmuggleCLTE(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Method:           "POST",
		URL:              "/",
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
		Body: "hello",
	}
	got := mustReqBytes(t, f)
	// CL 原样保留(走私意图),body 走 chunked 成帧(整段一块)。
	if !bytes.Contains(got, []byte("Content-Length: 6\r\n")) {
		t.Errorf("走私用例应保留手写 CL=6, got %q", got)
	}
	wantBody := "5\r\nhello\r\n0\r\n\r\n"
	if !bytes.Contains(got, []byte(wantBody)) {
		t.Errorf("body 应 chunked 成帧, got %q", got)
	}
}

// 回归防线:字段全不设 -> 输出与改动前逐字节一致(纯字面 body,无编码/成帧/自动 CL)。
func TestSerializeHTTPReq_NoCodingRegression(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Method:  "GET",
		URL:     "/",
		Headers: scenario.HeaderMap{{Key: "Host", Value: "example.com"}},
		Body:    "plain",
	}
	got := mustReqBytes(t, f)
	want := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nplain"
	if string(got) != want {
		t.Errorf("无编码回归 got %q, want %q", got, want)
	}
}

// 回归防线:multipart 作 body + auto_content_length: true -> CL == multipart 序列化长度
// (CE 之后、TE 之前的基准;此用例无 CE/TE,基准 = multipart 原始字节)。
// 覆盖 httpBody 走 multipart 出口 + applyAutoContentLength 覆盖占位 CL 的组合,
// 此前 multipart_test 只断言 CL 非 0,未在 CL 头已存在(原位覆盖)语境下回归。
func TestSerializeHTTPReq_MultipartAutoCL(t *testing.T) {
	f := &scenario.HTTPReqFields{
		Method:            "POST",
		URL:               "/upload",
		AutoContentLength: true,
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"},
			{Key: "Content-Length", Value: "0"}, // 占位,应被原位覆盖为 multipart 实际长度
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts: []scenario.MultipartPart{
				{Headers: scenario.HeaderMap{{Key: "Content-Disposition", Value: `form-data; name="f"`}},
					Body: "payload"},
			},
		},
	}
	got := mustReqBytes(t, f)
	// multipart 序列化后的实际字节(part headers 由 builder 拼装),从输出中取 CL 值正向核对。
	clLine := extractContentLength(t, got)
	wantBody := "------=_pMaker_0001\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\npayload\r\n------=_pMaker_0001--\r\n"
	wantCL := "Content-Length: " + strconv.Itoa(len(wantBody))
	if clLine != wantCL {
		t.Errorf("multipart+autoCL 应覆盖 CL 为 %s, got %s", wantCL, clLine)
	}
	// CL 头位置不变(占位头在 Content-Type 之后,原位覆盖)。
	if !bytes.Contains(got, []byte("Content-Type: multipart/form-data; boundary=----=_pMaker_0001\r\n"+wantCL+"\r\n")) {
		t.Errorf("CL 应在原位置(Content-Type 后)被覆盖, got %q", got)
	}
}

// extractContentLength 从序列化字节中取出 "Content-Length: N" 行,便于正向断言。
func extractContentLength(t *testing.T, b []byte) string {
	t.Helper()
	for l := range strings.SplitSeq(string(b), "\r\n") {
		if len(l) >= len("content-length:") && strings.EqualFold(l[:len("content-length:")], "content-length:") {
			return l
		}
	}
	t.Fatalf("未找到 Content-Length 行: %q", b)
	return ""
}
