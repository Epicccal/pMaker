package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 multipart_consistency.go 的边界分支,补足 multipart_test.go 中
// TestMultipartConsistencyWarnings 未走的路径:http_response / eml_data 层、
// flows 的 message 遍历、quoted boundary 解析、Content-Type 缺 boundary= 参数、
// nil scenario 守卫。告警为软告警(非硬错),通过 scenario.Warnings 驱动。

// multiStackScenario 把一个 payload 生产层(含 multipart)包进 standalone packet 的
// eth/ipv4/tcp 之上,便于复用 Warnings 路径。layerType 区分 http_request/http_response/eml_data。
func multiStackScenario(layerType string, fields any) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
				{Type: layerType, Fields: fields},
			},
		}},
	}
}

// multipartEML 构造一个带 multipart 的 eml_data 层,Content-Type 由参数控制。
func multipartEML(ct string, m *scenario.MultipartBody) *scenario.EMLDataFields {
	headers := scenario.HeaderMap{
		{Key: "From", Value: "a@b"},
		{Key: "MIME-Version", Value: "1.0"},
	}
	if ct != "" {
		headers = append(headers, scenario.HeaderEntry{Key: "Content-Type", Value: ct})
	}
	return &scenario.EMLDataFields{Headers: headers, Multipart: m}
}

// multipartHTTPResp 构造一个带 multipart 的 http_response 层,Content-Type 由参数控制。
func multipartHTTPResp(ct string, m *scenario.MultipartBody) *scenario.HTTPRespFields {
	headers := scenario.HeaderMap{}
	if ct != "" {
		headers = append(headers, scenario.HeaderEntry{Key: "Content-Type", Value: ct})
	}
	return &scenario.HTTPRespFields{Status: 200, Headers: headers, Multipart: m}
}

func warningsContain(ws []scenario.Diagnostic, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w.Message, sub) {
			return true
		}
	}
	return false
}

// TestMultipartConsistency_HTTPResponseLayer: http_response 层含 multipart 也能被扫到
// (覆盖 checkLayerMultipartConsistency 的 *HTTPRespFields case)。
func TestMultipartConsistency_HTTPResponseLayer(t *testing.T) {
	// 缺 Content-Type → 告警。
	s := multiStackScenario("http_response", multipartHTTPResp("", &scenario.MultipartBody{
		Parts: []scenario.MultipartPart{{Body: "x"}},
	}))
	if !warningsContain(scenario.Warnings(s), "缺 Content-Type") {
		t.Fatalf("期望 http_response 缺 Content-Type 告警,得到 %v", scenario.Warnings(s))
	}

	// boundary 一致 → 无 boundary 相关告警。
	s = multiStackScenario("http_response", multipartHTTPResp(
		"multipart/form-data; boundary=----=_pMaker_0001",
		&scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}},
	))
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w.Message, "boundary") || strings.Contains(w.Message, "Content-Type") {
			t.Fatalf("http_response 一致场景不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_EMLDataLayer: eml_data 层含 multipart 也能被扫到
// (覆盖 checkLayerMultipartConsistency 的 *EMLDataFields case)。
func TestMultipartConsistency_EMLDataLayer(t *testing.T) {
	// boundary 不一致 → 告警。
	s := multiStackScenario("eml_data", multipartEML(
		"multipart/mixed; boundary=wrong",
		&scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}},
	))
	if !warningsContain(scenario.Warnings(s), "不一致") {
		t.Fatalf("期望 eml_data boundary 不一致告警,得到 %v", scenario.Warnings(s))
	}

	// boundary 一致(默认值)→ 无 boundary 相关告警。
	s = multiStackScenario("eml_data", multipartEML(
		"multipart/mixed; boundary=----=_pMaker_0001",
		&scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}},
	))
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w.Message, "boundary") || strings.Contains(w.Message, "Content-Type") {
			t.Fatalf("eml_data 一致场景不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_QuotedBoundary: Content-Type 头里 boundary 值带双引号
// (RFC 2046 §5.1.1 允许 quoted-string),解析去引号后与 multipart 实际 boundary 一致 → 无告警。
func TestMultipartConsistency_QuotedBoundary(t *testing.T) {
	s := multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: `multipart/form-data; boundary="my-boundary_123"`},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "my-boundary_123",
			Parts:    []scenario.MultipartPart{{Body: "x"}},
		},
	})
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w.Message, "boundary") {
			t.Fatalf("quoted boundary 去引号后一致不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_CTWithoutBoundaryParam: Content-Type 头存在但未带 boundary= 参数
// (parseBoundaryParam 返回空串)→ 专用告警。
func TestMultipartConsistency_CTWithoutBoundaryParam(t *testing.T) {
	s := multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data"},
		},
		Multipart: &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}},
	})
	if !warningsContain(scenario.Warnings(s), "未带 boundary=") {
		t.Fatalf("期望 Content-Type 缺 boundary= 参数告警,得到 %v", scenario.Warnings(s))
	}
}

// TestMultipartConsistency_FlowMessages: 含 multipart 的层出现在 flow 的 message stack 里
// 也能被扫到(覆盖 CheckMultipartConsistency 的 flows 遍历分支)。
func TestMultipartConsistency_FlowMessages(t *testing.T) {
	// flow message 里 http_response 缺 Content-Type → 告警定位含 flow 标签。
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Flows: []scenario.FlowSpec{{
			Name: "http-upload",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80, ClientISN: 1000, ServerISN: 5000}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
			},
			Messages: []scenario.Message{{
				From: "dst",
				Stack: []scenario.Layer{
					{Type: "http_response", Fields: multipartHTTPResp("", &scenario.MultipartBody{
						Parts: []scenario.MultipartPart{{Body: "x"}},
					})},
				},
			}},
		}},
	}
	ws := scenario.Warnings(s)
	if !warningsContain(ws, "缺 Content-Type") || !warningsContain(ws, "http-upload") {
		t.Fatalf("期望 flow message 缺 Content-Type 告警且含 flow 名,得到 %v", ws)
	}
}

// TestMultipartConsistency_NilScenario: nil scenario 与无 multipart 的层不误报。
func TestMultipartConsistency_NilScenario(t *testing.T) {
	if ws := scenario.CheckMultipartConsistency(nil); ws != nil {
		t.Fatalf("nil scenario 期望无告警,得到 %v", ws)
	}
	// 无 multipart 的 http_request → 不告警。
	s := multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{{Key: "Content-Type", Value: "text/plain"}},
		Body:    "x",
	})
	if ws := scenario.CheckMultipartConsistency(s); len(ws) != 0 {
		t.Fatalf("无 multipart 层不应告警,得到 %v", ws)
	}
}

// TestMultipartConsistency_BoundaryCollision: part 编码后 body 内出现独占一行的
// `--<boundary>` 分界符 → boundary 碰撞告警(RFC 2046 §5.1.1)。断言告警出现在
// scenario.Warnings 输出中且带稳定 code 与声明级 path,锁定告警经 Warnings 回流 CLI/MCP。
func TestMultipartConsistency_BoundaryCollision(t *testing.T) {
	boundary := "----=_pMaker_0001"
	s := multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=" + boundary},
		},
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{
				{Body: "前置内容\r\n--" + boundary + "\r\n后续内容"}, // 碰撞行:独占一行
			},
		},
	})
	ws := scenario.Warnings(s)
	found := false
	for _, w := range ws {
		if w.Code != scenario.CodeMultipartBoundaryCollision {
			continue
		}
		found = true
		if w.Path != "packets[0].stack[3].multipart.parts[0]" {
			t.Errorf("碰撞告警 path 应为声明级 part 路径,得到 %q", w.Path)
		}
		if !strings.Contains(w.Message, boundary) {
			t.Errorf("碰撞告警文案应含 boundary,得到 %q", w.Message)
		}
	}
	if !found {
		t.Fatalf("boundary 碰撞应经 Warnings 产出 %q 告警,得到 %v", scenario.CodeMultipartBoundaryCollision, ws)
	}

	// 行内子串(未独占一行)不告警,避免误报。
	s = multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=" + boundary},
		},
		Multipart: &scenario.MultipartBody{
			Parts: []scenario.MultipartPart{
				{Body: "行内出现 --" + boundary + " 子串但未独占一行"},
			},
		},
	})
	for _, w := range scenario.Warnings(s) {
		if w.Code == scenario.CodeMultipartBoundaryCollision {
			t.Fatalf("行内子串不应触发碰撞告警,得到 %v", w)
		}
	}

	// 编码后碰撞:quoted-printable 编码后的字节撞 boundary 同样告警(检查基于编码后字节,
	// 与 builder.serializeMultipart 共享 EncodeMultipartPart,口径一致)。边界用不含 '=' 的
	// boundary:QP 会把 '=' 编为 =3D,含 '=' 的 boundary 经 QP 后必然失配,天然不可能碰撞;
	// 不含 '=' 时 QP 对可打印 ASCII 原样保留,碰撞行编码后不变,照常命中。
	// (base64 字母表不含 '-',编码后也不可能碰撞,故不作碰撞载体。)
	qpBoundary := "my-boundary-123"
	s = multiStackScenario("http_request", &scenario.HTTPReqFields{
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/form-data; boundary=" + qpBoundary},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: qpBoundary,
			Parts: []scenario.MultipartPart{
				{
					Encoding: "quoted-printable",
					Headers:  scenario.HeaderMap{{Key: "Content-Transfer-Encoding", Value: "quoted-printable"}},
					Body:     "前置\r\n--" + qpBoundary + "\r\n后续",
				},
			},
		},
	})
	if !warningsContain(scenario.Warnings(s), "boundary 分界符") {
		t.Fatalf("编码后碰撞同样应告警,得到 %v", scenario.Warnings(s))
	}
}
