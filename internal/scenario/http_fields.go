package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 http_request / http_response 字段的「合法基线」校验,与 FTP/SMTP/Telnet
// 的校验思路对齐:校验只判合法性,绝不改变序列化行为(序列化在 builder/http.go)。
//
// HTTP 较 FTP/SMTP 宽松:method / url / status / reason 等字段空值由 builder 走合理默认
// (GET / / 200 / StatusText),故空值合法、不报错。version 非空时需符合 HTTP/x.y 文法、
// status 非空需在 100-599——这两项是「防 YAML 笔误」级别的护栏。
//
// 刻意不校验请求行 / 状态行字段的 CR/LF:CRLF 注入(请求走私)、响应拆分是 HTTP 安全测试
// 的经典畸形场景,用结构化字段直接在 method/url/reason 里写 \r\n 表达最自然,属于本工具
// 「畸形包必须能构造」的立身之本,不应拦截。需要精确字节的畸形(非标 version、私有方法名
// 等)另可走 payload / payload_hex 原始字节兜底。

// httpVersionOK 判断 version 字段是否符合 HTTP/x.y 文法(大小写敏感,HTTP 为大写)。
// 空值合法(由 builder 默认 HTTP/1.1),不在此校验。
func httpVersionOK(v string) bool {
	if !strings.HasPrefix(v, "HTTP/") {
		return false
	}
	rest := v[len("HTTP/"):]
	// 形如 1.1 / 2 / 3.0:至少一位数字,可选 '.'+数字。
	major, minor, hasDot := strings.Cut(rest, ".")
	if !hasDot {
		return isASCIIDigits(rest)
	}
	return major != "" && isASCIIDigits(major) && minor != "" && isASCIIDigits(minor)
}

// isASCIIDigits 报告 s 非空且仅由 ASCII 数字组成。
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validateHTTPReqFields 校验 http_request 字段组合的合法性。
//
//   - method / url / version 空值合法(builder 走默认 GET / / HTTP/1.1);
//   - version 非空时需符合 HTTP/x.y,否则报错并引导 payload / payload_hex。
//
// 不校验 method / url / version 的 CR/LF:CRLF 注入(请求走私)是受支持的畸形构造场景。
func validateHTTPReqFields(f *HTTPReqFields) error {
	if f.Version != "" && !httpVersionOK(f.Version) {
		return fmt.Errorf("version %q 非 HTTP/x.y 文法(非标 version 请用 payload / payload_hex)", f.Version)
	}
	return nil
}

// validateHTTPRespFields 校验 http_response 字段组合的合法性。
//
//   - status 空值(0)合法(builder 默认 200);非空需在 100-599;
//   - version 非空时需符合 HTTP/x.y,否则报错并引导 payload / payload_hex。
//
// 不校验 version / reason 的 CR/LF:响应拆分是受支持的畸形构造场景。
func validateHTTPRespFields(f *HTTPRespFields) error {
	if f.Status != 0 && (f.Status < 100 || f.Status > 599) {
		return fmt.Errorf("status %d 越界(合法 100-599;非标 status 请用 payload / payload_hex)", f.Status)
	}
	if f.Version != "" && !httpVersionOK(f.Version) {
		return fmt.Errorf("version %q 非 HTTP/x.y 文法(非标 version 请用 payload / payload_hex)", f.Version)
	}
	return nil
}

// validateHTTPMultipart 校验 http_request/http_response 的 multipart 子结构与 body 的互斥,
// 并递归校验 multipart 内部合法性。multipart 本身就是 body,故与字面 body 互斥。
func validateHTTPMultipart(body string, m *MultipartBody) error {
	if m == nil {
		return nil
	}
	if body != "" {
		return fmt.Errorf("multipart 与 body 不可同设(multipart 本身即为请求/响应体)")
	}
	return validateMultipart(m)
}
