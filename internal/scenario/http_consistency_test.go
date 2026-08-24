package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 HTTP CE/TE 一致性告警(CheckHTTPConsistency)与响应侧 auto_content_length
// 语义告警(CheckHTTPRespConsistency),全部为非硬错(畸形用例可故意不一致)。

// httpConsistencyScenario 构造仅含单 HTTP 层 packet 的 Scenario,返回 Warnings。
func httpConsistencyScenario(layer scenario.Layer) []string {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{layer}}}}
	return scenario.Warnings(s)
}

func hasWarning(warns []string, substr string) bool {
	for _, w := range warns {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestHTTPConsistency_NoWarningWhenClean(t *testing.T) {
	// 自洽:TE=chunked + Transfer-Encoding 头声明 chunked,无 CL,chunked 末位。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Transfer-Encoding", Value: "chunked"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if len(warns) != 0 {
		t.Errorf("自洽配置不应告警, got %v", warns)
	}
}

func TestHTTPConsistency_TEMissingHeader(t *testing.T) {
	// TE 非空但缺 Transfer-Encoding 头 -> 告警。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "缺 Transfer-Encoding 头") {
		t.Errorf("TE 非空缺头应告警, got %v", warns)
	}
}

func TestHTTPConsistency_TEHeaderMismatch(t *testing.T) {
	// TE=chunked 但头写 gzip -> 告警。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Transfer-Encoding", Value: "gzip"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "不符") {
		t.Errorf("TE 与头不符应告警, got %v", warns)
	}
}

func TestHTTPConsistency_CEMissingHeader(t *testing.T) {
	// CE 非空但缺 Content-Encoding 头 -> 告警。
	f := &scenario.HTTPRespFields{
		Status:          200,
		ContentEncoding: scenario.CodingList{"GZIP"},
		Headers:         scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
		Body:            "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "缺 Content-Encoding 头") {
		t.Errorf("CE 非空缺头应告警, got %v", warns)
	}
}

func TestHTTPConsistency_CEHeaderMatch(t *testing.T) {
	// CE=gzip + 头 Content-Encoding: gzip,大小写无关 -> 无告警。
	f := &scenario.HTTPRespFields{
		Status:            200,
		AutoContentLength: true,
		ContentEncoding:   scenario.CodingList{"GZIP"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Encoding", Value: "GZIP"},
			{Key: "Content-Length", Value: "0"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if hasWarning(warns, "不符") || hasWarning(warns, "缺 Content-Encoding") {
		t.Errorf("CE 与头一致不应告警不符, got %v", warns)
	}
}

func TestHTTPConsistency_CLTEConflict(t *testing.T) {
	// TE 非空 + 显式 CL 头(auto=false 走私路径)-> CL+TE 冲突告警。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "Content-Length 头与 transfer_encoding") {
		t.Errorf("CL+TE 并存应告警走私特征, got %v", warns)
	}
}

func TestHTTPConsistency_ChunkedNotLast(t *testing.T) {
	// TE=[chunked, gzip]:chunked 不在末位 -> 告警。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED", "GZIP"},
		Headers:          scenario.HeaderMap{{Key: "Transfer-Encoding", Value: "chunked, gzip"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "chunked 不在末位") {
		t.Errorf("chunked 非末位应告警, got %v", warns)
	}
}

func TestHTTPConsistency_DoubleChunked(t *testing.T) {
	// TE=[chunked, chunked]:双 chunked -> 异常编码栈告警。
	f := &scenario.HTTPRespFields{
		Status:           200,
		TransferEncoding: scenario.CodingList{"CHUNKED", "CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Transfer-Encoding", Value: "chunked, chunked"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "异常编码栈") {
		t.Errorf("双 chunked 应告警异常编码栈, got %v", warns)
	}
}

func TestHTTPRespConsistency_204WithBodyAutoCL(t *testing.T) {
	// 204 + body + auto=true -> 告警。
	f := &scenario.HTTPRespFields{
		Status:            204,
		AutoContentLength: true,
		Headers:           scenario.HeaderMap{{Key: "Content-Length", Value: "0"}},
		Body:              "should not be here",
	}
	warns := scenario.CheckHTTPRespConsistency("test", "http_response", f)
	if !hasWarning(warns, "204") {
		t.Errorf("204+body+auto 应告警, got %v", warns)
	}
}

func TestHTTPRespConsistency_204NoBodyNoWarning(t *testing.T) {
	// 204 无 body + auto=true -> 不告警(body 为空)。
	f := &scenario.HTTPRespFields{
		Status:            204,
		AutoContentLength: true,
		Headers:           scenario.HeaderMap{{Key: "Content-Length", Value: "0"}},
	}
	warns := scenario.CheckHTTPRespConsistency("test", "http_response", f)
	if len(warns) != 0 {
		t.Errorf("204 无 body 不应告警, got %v", warns)
	}
}

func TestHTTPRespConsistency_304AlwaysWarns(t *testing.T) {
	// 304 + auto=true -> 无论 body 是否为空均告警。
	f := &scenario.HTTPRespFields{
		Status:            304,
		AutoContentLength: true,
		Headers:           scenario.HeaderMap{{Key: "Content-Length", Value: "0"}},
	}
	warns := scenario.CheckHTTPRespConsistency("test", "http_response", f)
	if !hasWarning(warns, "304") {
		t.Errorf("304+auto 应告警(无论 body), got %v", warns)
	}
}

func TestHTTPRespConsistency_AutoOffNoWarning(t *testing.T) {
	// auto=false -> 不告警(用户手写 CL)。
	f := &scenario.HTTPRespFields{
		Status:  204,
		Headers: scenario.HeaderMap{{Key: "Content-Length", Value: "10"}},
		Body:    "data",
	}
	warns := scenario.CheckHTTPRespConsistency("test", "http_response", f)
	if len(warns) != 0 {
		t.Errorf("auto=false 不应告警, got %v", warns)
	}
}

// --- request 侧一致性告警(此前 consistency 测试全部用 response,请求侧分派无覆盖)---

func TestHTTPConsistency_RequestCLTEConflict(t *testing.T) {
	// 请求侧:TE=chunked + 手写 CL(auto=false 走私路径)-> CL+TE 冲突告警。
	f := &scenario.HTTPReqFields{
		Method:           "POST",
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Length", Value: "6"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPReqLayer(t, f))
	if !hasWarning(warns, "Content-Length 头与 transfer_encoding") {
		t.Errorf("请求侧 CL+TE 并存应告警走私特征, got %v", warns)
	}
}

func TestHTTPConsistency_RequestTEMissingHeader(t *testing.T) {
	// 请求侧:TE 非空但缺 Transfer-Encoding 头 -> 告警。
	f := &scenario.HTTPReqFields{
		Method:           "POST",
		TransferEncoding: scenario.CodingList{"CHUNKED"},
		Headers:          scenario.HeaderMap{{Key: "Host", Value: "example.com"}},
		Body:             "hello",
	}
	warns := httpConsistencyScenario(mustHTTPReqLayer(t, f))
	if !hasWarning(warns, "缺 Transfer-Encoding 头") {
		t.Errorf("请求侧 TE 非空缺头应告警, got %v", warns)
	}
}

// --- CE/TE 与头顺序、重复 token 的双向包含比对 ---

func TestHTTPConsistency_CEOrderSwappedWarns(t *testing.T) {
	// 列表 [deflate, gzip] 对应头文本应写 "deflate, gzip";头写反序 "gzip, deflate"
	// 双向包含仍认为一致(token 集合相同),不应告警"不符"。
	// (本项目一致性比对是宽松集合包含,不校验顺序——RFC 编码顺序由外置列表表达,头文本自由。)
	f := &scenario.HTTPRespFields{
		Status:          200,
		ContentEncoding: scenario.CodingList{"DEFLATE", "GZIP"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Encoding", Value: "gzip, deflate"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if hasWarning(warns, "不符") {
		t.Errorf("头 token 集合相同(顺序不同)不应告警不符, got %v", warns)
	}
}

func TestHTTPConsistency_HeaderExtraTokenWarns(t *testing.T) {
	// 头比列表多一个 token(头 "gzip, deflate",列表仅 [gzip])-> 反向包含命中,告警不符。
	f := &scenario.HTTPRespFields{
		Status:          200,
		ContentEncoding: scenario.CodingList{"GZIP"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Encoding", Value: "gzip, deflate"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if !hasWarning(warns, "不符") {
		t.Errorf("头多 token 应告警不符, got %v", warns)
	}
}

func TestHTTPConsistency_HeaderDuplicateTokenNoFalseWarn(t *testing.T) {
	// 头含重复 token("gzip, gzip")与列表 [gzip] 双向包含:gzip 在列表中、
	// 重复的 gzip 也在列表中 -> 不应误报。
	f := &scenario.HTTPRespFields{
		Status:          200,
		ContentEncoding: scenario.CodingList{"GZIP"},
		Headers: scenario.HeaderMap{
			{Key: "Content-Encoding", Value: "gzip, gzip"},
		},
		Body: "hello",
	}
	warns := httpConsistencyScenario(mustHTTPRespLayer(t, f))
	if hasWarning(warns, "不符") {
		t.Errorf("头重复 token 不应误报不符, got %v", warns)
	}
}

// --- flow 路径一致性告警(此前只测 packet 路径,CheckHTTPConsistency 的 flow 分支无覆盖)---

func TestHTTPConsistency_FlowMessageWarns(t *testing.T) {
	// flow.messages 内的 http_response 带 TE 不自洽(缺 Transfer-Encoding 头)-> 应触发告警。
	// 验证 CheckHTTPConsistency 的 s.Flows 分支(而非 s.Packets)被走到,且告警定位含 flow 名。
	// 走 Load + Validate + Warnings 完整路径(对齐 ftp_consistency_test 的 loadWarnings 范式)。
	yamlText := `link_type: ethernet
seed: 42
flows:
  - name: http-flow
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response:
              status: 200
              transfer_encoding: chunked
              headers:
                Content-Type: text/plain
              body: "hello"
`
	path := writeScenario(t, "http_consistency_flow.yaml", yamlText)
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate 失败: %v", err)
	}
	warns := scenario.Warnings(s)
	if !hasWarning(warns, "缺 Transfer-Encoding 头") {
		t.Errorf("flow 内 HTTP 层 TE 缺头应告警, got %v", warns)
	}
	// 告警定位应含 flow 名(http-flow),而非 packet[N]。
	if !hasWarning(warns, "http-flow") {
		t.Errorf("flow 路径告警定位应含 flow 名, got %v", warns)
	}
}
