package builder

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeHTTPReq/Resp:把结构化 HTTP 序列化为 TCP payload 字节。
// 头按 YAML 声明顺序输出(保留原序、支持重复头如多个 Set-Cookie)。
func serializeHTTPReq(f *scenario.HTTPReqFields) []byte {
	method := orDefault(f.Method, "GET")
	url := orDefault(f.URL, "/")
	ver := orDefault(f.Version, "HTTP/1.1")

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, url, ver)
	writeHeaders(&b, f.Headers, len(f.Body))
	b.WriteString("\r\n")
	b.WriteString(f.Body)
	return []byte(b.String())
}

func serializeHTTPResp(f *scenario.HTTPRespFields) []byte {
	ver := orDefault(f.Version, "HTTP/1.1")
	status := f.Status
	if status == 0 {
		status = 200
	}
	reason := orDefault(f.Reason, http.StatusText(status))

	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", ver, status, reason)
	writeHeaders(&b, f.Headers, len(f.Body))
	b.WriteString("\r\n")
	b.WriteString(f.Body)
	return []byte(b.String())
}

// writeHeaders 按 HeaderMap 原序输出头。遇任意大小写的 Content-Length 且值为 "auto"
// 时替换为 bodyLen;重复 Content-Length 的每个 auto 都替换为同一长度(合规用例不会重复
// Content-Length;若用户故意写重复且想差异化,应改用具体值或 raw 兜底)。
func writeHeaders(b *strings.Builder, h scenario.HeaderMap, bodyLen int) {
	h.Range(func(k, v string) {
		if strings.EqualFold(k, "Content-Length") && v == "auto" {
			v = strconv.Itoa(bodyLen)
		}
		fmt.Fprintf(b, "%s: %s\r\n", k, v)
	})
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
