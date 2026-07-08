package builder

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeHTTPReq/Resp:把结构化 HTTP 序列化为 TCP payload 字节。
// 头按 key 排序输出以保证确定性(保留原序留待后续)。
func serializeHTTPReq(f *scenario.HTTPReqFields) []byte {
	method := orDefault(f.Method, "GET")
	url := orDefault(f.Url, "/")
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

func writeHeaders(b *strings.Builder, h map[string]string, bodyLen int) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := h[k]
		if strings.EqualFold(k, "Content-Length") && v == "auto" {
			v = strconv.Itoa(bodyLen)
		}
		fmt.Fprintf(b, "%s: %s\r\n", k, v)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
