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

func warningsContain(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// TestMultipartConsistency_HTTPResponseLayer: http_response 层含 multipart 也能被扫到
// (CheckMultipartConsistency 的 HTTPRespFields 分支),缺 Content-Type 时告警。
func TestMultipartConsistency_HTTPResponseLayer(t *testing.T) {
	s := multiStackScenario("http_response",
		multipartHTTPResp("", &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}}))
	ws := scenario.Warnings(s)
	if !warningsContain(ws, "缺 Content-Type") {
		t.Fatalf("http_response 缺 Content-Type 应告警,得到 %v", ws)
	}
	// 一致场景不告警。
	s = multiStackScenario("http_response",
		multipartHTTPResp("multipart/mixed; boundary=----=_pMaker_0001", &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}}))
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w, "boundary") || strings.Contains(w, "Content-Type") {
			t.Fatalf("http_response 一致场景不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_EMLDataLayer: eml_data 层含 multipart 也能被扫到
// (CheckMultipartConsistency 的 EMLDataFields 分支),缺 Content-Type 时告警。
func TestMultipartConsistency_EMLDataLayer(t *testing.T) {
	s := multiStackScenario("eml_data",
		multipartEML("", &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}}))
	ws := scenario.Warnings(s)
	if !warningsContain(ws, "缺 Content-Type") {
		t.Fatalf("eml_data 缺 Content-Type 应告警,得到 %v", ws)
	}
	// 一致场景不告警。
	s = multiStackScenario("eml_data",
		multipartEML("multipart/mixed; boundary=----=_pMaker_0001", &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}}))
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w, "boundary") || strings.Contains(w, "Content-Type") {
			t.Fatalf("eml_data 一致场景不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_QuotedBoundary: Content-Type 头里 boundary 值带双引号
// (RFC 2046 quoted-string),去引号后与实际一致 → 不告警。
func TestMultipartConsistency_QuotedBoundary(t *testing.T) {
	s := multiStackScenario("eml_data", multipartEML("multipart/mixed; boundary=\"----=_pMaker_0001\"", &scenario.MultipartBody{
		Parts: []scenario.MultipartPart{{Body: "x"}},
	}))
	for _, w := range scenario.Warnings(s) {
		if strings.Contains(w, "boundary") {
			t.Fatalf("quoted boundary 去引号后一致不应告警,得到 %v", scenario.Warnings(s))
		}
	}
}

// TestMultipartConsistency_CTWithoutBoundaryParam: Content-Type 头存在但未带 boundary= 参数
// → 告警(与缺头区分)。
func TestMultipartConsistency_CTWithoutBoundaryParam(t *testing.T) {
	s := multiStackScenario("eml_data", multipartEML("multipart/mixed", &scenario.MultipartBody{
		Parts: []scenario.MultipartPart{{Body: "x"}},
	}))
	if !warningsContain(scenario.Warnings(s), "未带 boundary=") {
		t.Fatalf("Content-Type 未带 boundary= 参数应告警,得到 %v", scenario.Warnings(s))
	}
}

// TestMultipartConsistency_FlowMessages: 含 multipart 的层出现在 flow 的 message stack 里
// 也能被扫到(flowLabel 定位、messages 遍历分支)。
func TestMultipartConsistency_FlowMessages(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Flows: []scenario.FlowSpec{{
			Name: "http-upload",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80}},
			},
			Messages: []scenario.Message{{
				From: "src",
				Stack: []scenario.Layer{
					{Type: "http_request", Fields: &scenario.HTTPReqFields{
						// 故意不给 Content-Type 头,触发缺头告警。
						Multipart: &scenario.MultipartBody{Parts: []scenario.MultipartPart{{Body: "x"}}},
					}},
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
// scenario.Warnings 输出中,锁定告警经 Warnings 回流 CLI/MCP(而非 builder 阶段 slog)。
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
	if !warningsContain(scenario.Warnings(s), "boundary 分界符") {
		t.Fatalf("boundary 碰撞应经 Warnings 产出告警,得到 %v", scenario.Warnings(s))
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
		if strings.Contains(w, "boundary 分界符") {
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
