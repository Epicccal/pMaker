package scenario_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 http_request / http_response 字段校验(validateHTTPReqFields /
// validateHTTPRespFields),通过 Validate 直接驱动。校验只判合法性,不改变序列化。
//
// 覆盖点:
//   - 合法场景通过(空字段走 builder 默认、HTTP/1.1、状态 100-599);
//   - version 非 HTTP/x.y 文法被拒并引导 payload/payload_hex;
//   - status 越界(非 0 且不在 100-599)被拒;
//   - 请求行 / 状态行 CRLF 注入通过(请求走私 / 响应拆分是受支持的畸形构造,不拦截);
//   - coding 逐元素枚举(CE: gzip/deflate/deflate_raw/br/compress; TE: chunked/gzip/deflate/deflate_raw/compress);
//   - auto_content_length 与 TE 非空互斥;
//   - auto_content_length 且多 CL 头 -> 硬错;
//   - chunked 子结构依赖 TE 含 chunked; chunked.size 范围校验。

func mustHTTPReqLayer(t *testing.T, f *scenario.HTTPReqFields) scenario.Layer {
	t.Helper()
	return scenario.Layer{Type: "http_request", Fields: f}
}

func mustHTTPRespLayer(t *testing.T, f *scenario.HTTPRespFields) scenario.Layer {
	t.Helper()
	return scenario.Layer{Type: "http_response", Fields: f}
}

// httpValidateScenario 构造一个仅含单 HTTP 层 packet 的 Scenario 并跑 Validate。
// HTTP 层是 payload 生产层,放在 packet.stack 中 validateLayer 会被调用。
func httpValidateScenario(layer scenario.Layer) error {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{layer}}}}
	return scenario.Validate(s)
}

func TestValidateHTTPReqFieldsOK(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.HTTPReqFields
	}{
		{"全空走默认", &scenario.HTTPReqFields{}},
		{"完整请求", &scenario.HTTPReqFields{Method: "GET", URL: "/index.html", Version: "HTTP/1.1"}},
		{"HTTP/2", &scenario.HTTPReqFields{Method: "GET", URL: "/", Version: "HTTP/2"}},
		{"HTTP/3.0", &scenario.HTTPReqFields{Method: "POST", URL: "/api", Version: "HTTP/3.0"}},
		{"私有方法名合法", &scenario.HTTPReqFields{Method: "PURGE", URL: "/", Version: "HTTP/1.1"}},
		{"method含CRLF(请求走私)合法", &scenario.HTTPReqFields{Method: "GET\r\nX-Inject: 1", URL: "/", Version: "HTTP/1.1"}},
		{"url含CRLF(请求走私)合法", &scenario.HTTPReqFields{Method: "GET", URL: "/\nX-Inject: 1", Version: "HTTP/1.1"}},
	}
	for _, c := range cases {
		if err := httpValidateScenario(mustHTTPReqLayer(t, c.f)); err != nil {
			t.Errorf("%s: 期望通过,得到 %v", c.name, err)
		}
	}
}

func TestValidateHTTPReqFieldsRejectsBadVersion(t *testing.T) {
	for _, v := range []string{"1.1", "http/1.1", "HTTP", "HTTP/", "HTTP/x.y", "HTTP/1.", "HTTP/.1", "HTTP/1.1a"} {
		f := &scenario.HTTPReqFields{Method: "GET", URL: "/", Version: v}
		err := httpValidateScenario(mustHTTPReqLayer(t, f))
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Errorf("version %q 期望被拒并点名 version,得到 %v", v, err)
		}
	}
}

func TestValidateHTTPRespFieldsOK(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.HTTPRespFields
	}{
		{"全空走默认", &scenario.HTTPRespFields{}},
		{"完整响应", &scenario.HTTPRespFields{Version: "HTTP/1.1", Status: 200, Reason: "OK"}},
		{"HTTP/2 204", &scenario.HTTPRespFields{Version: "HTTP/2", Status: 204, Reason: "No Content"}},
		{"599边界", &scenario.HTTPRespFields{Status: 599}},
		{"100边界", &scenario.HTTPRespFields{Status: 100}},
		{"reason含CRLF(响应拆分)合法", &scenario.HTTPRespFields{Version: "HTTP/1.1", Status: 200, Reason: "OK\nSet-Cookie: x=1"}},
	}
	for _, c := range cases {
		if err := httpValidateScenario(mustHTTPRespLayer(t, c.f)); err != nil {
			t.Errorf("%s: 期望通过,得到 %v", c.name, err)
		}
	}
}

func TestValidateHTTPRespFieldsRejectsStatusRange(t *testing.T) {
	for _, st := range []int{-1, 99, 600, 1000} {
		f := &scenario.HTTPRespFields{Status: st}
		err := httpValidateScenario(mustHTTPRespLayer(t, f))
		if err == nil || !strings.Contains(err.Error(), "status") {
			t.Errorf("status %d 期望被拒并点名 status,得到 %v", st, err)
		}
	}
}

func TestValidateHTTPRespFieldsRejectsBadVersion(t *testing.T) {
	f := &scenario.HTTPRespFields{Version: "HTTP/abc", Status: 200}
	err := httpValidateScenario(mustHTTPRespLayer(t, f))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("version %q 期望被拒,得到 %v", f.Version, err)
	}
}

// --- 编码 / 成帧 / 自动 CL 校验 ---

func TestValidateHTTPCodings_OK(t *testing.T) {
	cases := []scenario.HTTPRespFields{
		{}, // 全不设
		{ContentEncoding: scenario.CodingList{"GZIP"}},
		{ContentEncoding: scenario.CodingList{"DEFLATE", "GZIP"}},  // 链式
		{ContentEncoding: scenario.CodingList{"BR"}},               // Brotli(仅 CE)
		{ContentEncoding: scenario.CodingList{"BR", "GZIP"}},       // 链式含 br
		{ContentEncoding: scenario.CodingList{"ZSTD"}},             // Zstandard(RFC 8478,仅 CE)
		{ContentEncoding: scenario.CodingList{"ZSTD", "GZIP"}},     // 链式含 zstd
		{ContentEncoding: scenario.CodingList{"COMPRESS"}},         // UNIX compress/LZW(CE 合法)
		{ContentEncoding: scenario.CodingList{"COMPRESS", "GZIP"}}, // 链式含 compress
		{TransferEncoding: scenario.CodingList{"CHUNKED"}},
		{TransferEncoding: scenario.CodingList{"CHUNKED", "GZIP"}},
		{TransferEncoding: scenario.CodingList{"GZIP"}},                // 仅 TE=gzip(无 chunked 也合法)
		{TransferEncoding: scenario.CodingList{"COMPRESS", "CHUNKED"}}, // compress 进 TE(相对 br 的净新增能力面)
		{TransferEncoding: scenario.CodingList{"COMPRESS"}},            // 仅 TE=compress(无 chunked 也合法)
		{TransferEncoding: scenario.CodingList{"CHUNKED"}, Chunked: &scenario.ChunkedOptions{Size: 8}},
		{TransferEncoding: scenario.CodingList{"CHUNKED"}, Chunked: &scenario.ChunkedOptions{Size: 0}},
		{AutoContentLength: true},
		{AutoContentLength: true, ContentEncoding: scenario.CodingList{"GZIP"}},
	}
	for i, c := range cases {
		if err := httpValidateScenario(mustHTTPRespLayer(t, &c)); err != nil {
			t.Errorf("[%d] %v: 期望通过,得到 %v", i, describeHTTPFields(c), err)
		}
	}
}

func TestValidateHTTPCodings_RejectInvalidCE(t *testing.T) {
	// CE 中放入 chunked(传输编码不是内容编码)。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		ContentEncoding: scenario.CodingList{"CHUNKED"},
	})); err == nil || !strings.Contains(err.Error(), "content_encoding") {
		t.Errorf("CE=CHUNKED 期望被拒,得到 %v", err)
	}
	// CE 中放入未知编码。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		ContentEncoding: scenario.CodingList{"BROTLI"},
	})); err == nil || !strings.Contains(err.Error(), "content_encoding") {
		t.Errorf("CE=BROTLI 期望被拒,得到 %v", err)
	}
}

func TestValidateHTTPCodings_CompressInBothCEAndTE(t *testing.T) {
	// compress(UNIX LZW)与 br 不同:CE 与 TE 均合法,两端都不应被拒。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		ContentEncoding: scenario.CodingList{"COMPRESS"},
	})); err != nil {
		t.Errorf("CE=COMPRESS 期望通过(CE 合法),得到 %v", err)
	}
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"COMPRESS"},
	})); err != nil {
		t.Errorf("TE=COMPRESS 期望通过(TE 合法,与 br 不同),得到 %v", err)
	}
}

func TestValidateHTTPCodings_RejectInvalidTE(t *testing.T) {
	// TE 中放入未知编码。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"UNKNOWN"},
	})); err == nil || !strings.Contains(err.Error(), "transfer_encoding") {
		t.Errorf("TE=UNKNOWN 期望被拒,得到 %v", err)
	}
	// br 仅限 content_encoding,放进 transfer_encoding 应被拒(br 不是标准传输编码)。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"BR"},
	})); err == nil || !strings.Contains(err.Error(), "transfer_encoding") {
		t.Errorf("TE=BR 期望被拒(br 仅限 content_encoding),得到 %v", err)
	}
	// zstd 仅限 content_encoding,放进 transfer_encoding 应被拒(zstd 不是标准传输编码)。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"ZSTD"},
	})); err == nil || !strings.Contains(err.Error(), "transfer_encoding") {
		t.Errorf("TE=ZSTD 期望被拒(zstd 仅限 content_encoding),得到 %v", err)
	}
}

func TestValidateHTTPCodings_AutoCLWithTE(t *testing.T) {
	cases := []struct {
		name string
		te   scenario.CodingList
	}{
		{"TE=chunked", scenario.CodingList{"CHUNKED"}},
		{"TE=gzip(定长也互斥)", scenario.CodingList{"GZIP"}},
		{"TE=链式", scenario.CodingList{"DEFLATE", "GZIP"}},
	}
	for _, c := range cases {
		err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
			AutoContentLength: true,
			TransferEncoding:  c.te,
		}))
		if err == nil || !strings.Contains(err.Error(), "auto_content_length") {
			t.Errorf("%s: 期望 auto_content_length 与 TE 互斥报错,得到 %v", c.name, err)
		}
	}
}

func TestValidateHTTPCodings_AutoCL_MultiCL(t *testing.T) {
	f := &scenario.HTTPRespFields{
		AutoContentLength: true,
		Headers: scenario.HeaderMap{
			{Key: "Content-Length", Value: "100"},
			{Key: "Content-Length", Value: "200"},
		},
	}
	err := httpValidateScenario(mustHTTPRespLayer(t, f))
	if err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("auto=true 且多 CL 头 期望被拒,得到 %v", err)
	}
}

func TestValidateHTTPCodings_ChunkedWithoutTE(t *testing.T) {
	// TE 不含 chunked 却给了 chunked:{ size: 8 } -> 硬错。
	err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		Chunked: &scenario.ChunkedOptions{Size: 8},
	}))
	if err == nil || !strings.Contains(err.Error(), "chunked") {
		t.Errorf("chunked 子结构但 TE 不含 chunked 期望被拒,得到 %v", err)
	}
	// 显式空 mapping 也报错。
	err = httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		Chunked: &scenario.ChunkedOptions{}, // size=0 仍是非 nil
	}))
	if err == nil || !strings.Contains(err.Error(), "chunked") {
		t.Errorf("chunked:{ } 但 TE 不含 chunked 期望被拒,得到 %v", err)
	}
}

func TestValidateHTTPCodings_ChunkedSizeRange(t *testing.T) {
	// size 负值 -> 硬错。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Chunked:          &scenario.ChunkedOptions{Size: -1},
	})); err == nil || !strings.Contains(err.Error(), "chunked.size") {
		t.Errorf("chunked.size < 0 期望被拒,得到 %v", err)
	}
	// size 超上限 -> 硬错。
	if err := httpValidateScenario(mustHTTPRespLayer(t, &scenario.HTTPRespFields{
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Chunked:          &scenario.ChunkedOptions{Size: scenario.MaxChunkedSize + 1},
	})); err == nil || !strings.Contains(err.Error(), "chunked.size") {
		t.Errorf("chunked.size 超上限期望被拒,得到 %v", err)
	}
}

// describeHTTPFields 返回字段的简要描述,便于报错定位。
func describeHTTPFields(f scenario.HTTPRespFields) string {
	var sb strings.Builder
	if f.AutoContentLength {
		sb.WriteString("autoCL=true ")
	}
	if len(f.ContentEncoding) > 0 {
		sb.WriteString("CE=")
		for i, c := range f.ContentEncoding {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(c)
		}
		sb.WriteByte(' ')
	}
	if len(f.TransferEncoding) > 0 {
		sb.WriteString("TE=")
		for i, c := range f.TransferEncoding {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(c)
		}
	}
	if f.Chunked != nil {
		fmt.Fprintf(&sb, " chunked.size=%d", f.Chunked.Size)
	}
	return sb.String()
}
