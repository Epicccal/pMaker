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
// 若设了 multipart,则 body 取自 serializeMultipart 的字节(取代字面 body),
// Content-Length: auto 按 multipart 实际长度计算。
func serializeHTTPReq(f *scenario.HTTPReqFields) ([]byte, error) {
	method := orDefault(f.Method, "GET")
	url := orDefault(f.URL, "/")
	ver := orDefault(f.Version, "HTTP/1.1")

	body, err := httpBody(f.Body, f.Multipart)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, url, ver)
	writeHeaders(&b, f.Headers, len(body))
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String()), nil
}

func serializeHTTPResp(f *scenario.HTTPRespFields) ([]byte, error) {
	ver := orDefault(f.Version, "HTTP/1.1")
	status := f.Status
	if status == 0 {
		status = 200
	}
	reason := orDefault(f.Reason, http.StatusText(status))

	body, err := httpBody(f.Body, f.Multipart)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", ver, status, reason)
	writeHeaders(&b, f.Headers, len(body))
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String()), nil
}

// httpBody 取 HTTP 的 body 字节:设了 multipart 则序列化 multipart(取代字面 body),
// 否则用字面 body。校验已保证二者互斥。
func httpBody(body string, m *scenario.MultipartBody) ([]byte, error) {
	if m != nil {
		return serializeMultipart(m)
	}
	return []byte(body), nil
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
