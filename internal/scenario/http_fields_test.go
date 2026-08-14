package scenario_test

import (
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
//   - 请求行 / 状态行 CRLF 注入通过(请求走私 / 响应拆分是受支持的畸形构造,不拦截)。

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
