package builder_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 HTTP 应用层序列化:回读 http_stack,断言请求行与 Host 头;
// 并覆盖 multipart 经 HTTP 层(请求/响应)端到端序列化(详见 multipart_test.go
// 的单元级序列化测试,此处补 http_request/http_response 分派 + 回读路径)。

// TestParseBackHTTP 回读 http_stack,断言 Ethernet/IPv4/TCP 与 HTTP 请求行。
func TestParseBackHTTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/http/stack.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	p := pkts[0]
	for _, lt := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP} {
		if p.Layer(lt) == nil {
			t.Errorf("缺少 %v 层", lt)
		}
	}
	app := p.ApplicationLayer()
	if app == nil || !bytes.Contains(app.Payload(), []byte("GET /index.html HTTP/1.1")) {
		t.Errorf("payload 不含预期的 HTTP 请求行")
	}
	if app != nil && !bytes.Contains(app.Payload(), []byte("Host: example.com")) {
		t.Errorf("payload 不含 Host 头")
	}
}

// TestSerializeHTTP_MultipartResponse 断言 http_response 分派 multipart:状态行 + 头 +
// multipart body;Content-Length: auto 取 multipart 实际长度(覆盖 serializeHTTPResp 路径,
// 与 multipart_test.go 中覆盖 serializeHTTPReq 的用例互补)。
func TestSerializeHTTP_MultipartResponse(t *testing.T) {
	f := &scenario.HTTPRespFields{
		Status: 206,
		Headers: scenario.HeaderMap{
			{Key: "Content-Type", Value: "multipart/byteranges; boundary=----=_pMaker_0001"},
			{Key: "Content-Length", Value: "auto"},
		},
		Multipart: &scenario.MultipartBody{
			Boundary: "----=_pMaker_0001",
			Parts:    []scenario.MultipartPart{{Body: "range-data"}},
		},
	}
	got := mustPayloadBytes(t, scenario.Layer{Type: "http_response", Fields: f})
	wantBody := "------=_pMaker_0001\r\n\r\nrange-data\r\n------=_pMaker_0001--\r\n"
	want := "HTTP/1.1 206 Partial Content\r\n" +
		"Content-Type: multipart/byteranges; boundary=----=_pMaker_0001\r\n" +
		"Content-Length: " + strconv.Itoa(len(wantBody)) + "\r\n" +
		"\r\n" +
		wantBody
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestParseBackHTTP_MultipartResponseE2E 端到端回读 http_response(multipart)包,
// 断言状态行、boundary 分界符行、终止 boundary 行均出现在 TCP payload。
func TestParseBackHTTP_MultipartResponseE2E(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10", TTL: u8ptr(64)}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 80, DPort: 49170, Flags: []string{"PSH", "ACK"}}},
				{Type: "http_response", Fields: &scenario.HTTPRespFields{
					Status: 200,
					Headers: scenario.HeaderMap{
						{Key: "Content-Type", Value: "multipart/form-data; boundary=----=_pMaker_0001"},
					},
					Multipart: &scenario.MultipartBody{
						Boundary: "----=_pMaker_0001",
						Parts: []scenario.MultipartPart{{
							Headers: scenario.HeaderMap{{Key: "Content-Disposition", Value: `form-data; name="r"`}},
							Body:    "ok",
						}},
					},
				}},
			},
		}},
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	read := readPackets(t, buf.Bytes())
	if len(read) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(read))
	}
	app := read[0].ApplicationLayer()
	if app == nil {
		t.Fatal("缺应用层 payload")
	}
	for _, want := range []string{
		"HTTP/1.1 200 OK",
		"------=_pMaker_0001\r\n",
		"------=_pMaker_0001--\r\n",
		`form-data; name="r"`,
	} {
		if !bytes.Contains(app.Payload(), []byte(want)) {
			t.Errorf("payload 不含 %q, got %q", want, app.Payload())
		}
	}
}
