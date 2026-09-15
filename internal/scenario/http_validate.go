package scenario

import (
	"fmt"
	"slices"
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

// maxChunkedSize 是 chunked.size 的固定上限。chunked 切块大小本无 RFC 上限,但设定固定
// 上限避免跨平台整数差异与异常配置(如误写 GB 级 size 导致内存爆炸)。合规测试用例的
// chunk 大小远小于此值。
const maxChunkedSize = 1 << 20 // 1 MiB

// validContentCodings 是 content_encoding 的合法元素集合(归一后大写形)。
// chunked 是传输编码,不是内容编码,出现在 CE 里 -> 报错。
var validContentCodings = map[string]bool{
	CodingGzip:       true,
	CodingDeflate:    true,
	CodingDeflateRaw: true,
	CodingBr:         true,
	CodingZstd:       true,
	CodingCompress:   true,
}

// validTransferCodings 是 transfer_encoding 的合法元素集合(归一后大写形)。
// br(Brotli)与 zstd(Zstandard)仅 Content-Encoding 专用,不是标准传输编码,出现在 TE 里 -> 报错。
var validTransferCodings = map[string]bool{
	CodingChunked:    true,
	CodingGzip:       true,
	CodingDeflate:    true,
	CodingDeflateRaw: true,
	CodingCompress:   true,
}

// validateHTTPReqFields 校验 http_request 字段组合的合法性。
//
//   - method / url / version 空值合法(builder 走默认 GET / / HTTP/1.1);
//   - version 非空时需符合 HTTP/x.y,否则报错并引导 payload / payload_hex;
//   - content_encoding / transfer_encoding 逐元素枚举(归一后大写形);
//   - auto_content_length 与 transfer_encoding 非空互斥(RFC 9112 §6.1 framing 语义);
//   - auto_content_length 且多 Content-Length 头 -> 硬错(覆盖目标歧义);
//   - chunked 子结构仅在 transfer_encoding 含 chunked 时有意义;size 合法范围。
//
// 不校验 method / url / version 的 CR/LF:CRLF 注入(请求走私)是受支持的畸形构造场景。
func validateHTTPReqFields(f *HTTPReqFields) error {
	if f.Version != "" && !httpVersionOK(f.Version) {
		return fmt.Errorf("version %q 非 HTTP/x.y 文法(非标 version 请用 payload / payload_hex)", f.Version)
	}
	if err := validateHTTPCodings(f.ContentEncoding, f.TransferEncoding, f.Chunked, f.AutoContentLength, f.Headers); err != nil {
		return err
	}
	return nil
}

// validateHTTPRespFields 校验 http_response 字段组合的合法性。
//
//   - status 空值(0)合法(builder 默认 200);非空需在 100-599;
//   - version 非空时需符合 HTTP/x.y,否则报错并引导 payload / payload_hex;
//   - content_encoding / transfer_encoding 逐元素枚举(归一后大写形);
//   - auto_content_length 与 transfer_encoding 非空互斥(RFC 9112 §6.1 framing 语义);
//   - auto_content_length 且多 Content-Length 头 -> 硬错(覆盖目标歧义);
//   - chunked 子结构仅在 transfer_encoding 含 chunked 时有意义;size 合法范围。
//
// 不校验 version / reason 的 CR/LF:响应拆分是受支持的畸形构造场景。
// 注:状态码语义(1xx/204/304)与 auto_content_length 的冲突是告警(http_consistency.go),不在此硬错。
// CONNECT 同 HEAD:响应层无请求方法上下文,不做处理。
func validateHTTPRespFields(f *HTTPRespFields) error {
	if f.Status != 0 && (f.Status < 100 || f.Status > 599) {
		return fmt.Errorf("status %d 越界(合法 100-599;非标 status 请用 payload / payload_hex)", f.Status)
	}
	if f.Version != "" && !httpVersionOK(f.Version) {
		return fmt.Errorf("version %q 非 HTTP/x.y 文法(非标 version 请用 payload / payload_hex)", f.Version)
	}
	if err := validateHTTPCodings(f.ContentEncoding, f.TransferEncoding, f.Chunked, f.AutoContentLength, f.Headers); err != nil {
		return err
	}
	return nil
}

// validateHTTPCodings 校验 http_request/http_response 共用的编码/成帧/自动 CL 字段组合
func validateHTTPCodings(ce, te CodingList, chunked *ChunkedOptions, autoCL bool, headers HeaderMap) error {
	teEff := te.Effective()
	ceEff := ce.Effective()

	// 逐元素枚举(归一后大写形)。
	for _, c := range ceEff {
		if !validContentCodings[c] {
			return fmt.Errorf("content_encoding 元素 %q 非法(合法:gzip/deflate/deflate_raw/br/zstd/compress;chunked 是传输编码不能放进 content_encoding;非标编码请用 payload / payload_hex)", c)
		}
	}
	for _, c := range teEff {
		if !validTransferCodings[c] {
			return fmt.Errorf("transfer_encoding 元素 %q 非法(合法:chunked/gzip/deflate/deflate_raw/compress;br/zstd 不是标准传输编码不能放进 transfer_encoding;非标编码请用 payload / payload_hex)", c)
		}
	}

	// auto_content_length 与 transfer_encoding 非空互斥(RFC 9112 §6.1 framing 语义)。
	// 依据是 HTTP framing 语义:TE 一旦存在,body 边界由 TE 接管,CL 的存在会令中间代理歧义,
	// 而非"是否可以计算出字节长度"——即便 transfer_encoding: gzip 最终 wire body 定长,
	// 发送方依然不得同时发 Content-Length。走私用例走 false + 头里手写 CL。
	if autoCL && len(teEff) > 0 {
		return fmt.Errorf("auto_content_length 与 transfer_encoding 非空互斥(RFC 9112 §6.1:含 Transfer-Encoding 的报文不得带 Content-Length;走私等需 TE+CL 共存的畸形请设 auto_content_length: false 并在 headers 手写 Content-Length)")
	}

	// auto_content_length 且多 Content-Length 头 -> 硬错(覆盖目标歧义)。
	if autoCL {
		clCount := 0
		headers.Range(func(k, _ string) {
			if strings.EqualFold(k, "Content-Length") {
				clCount++
			}
		})
		if clCount >= 2 {
			return fmt.Errorf("auto_content_length 在多 Content-Length 头时无法确定覆盖目标;如需构造多 CL 走私报文,请设 auto_content_length: false 并在 headers 里手写各 CL 值")
		}
	}

	// chunked 子结构仅在 transfer_encoding 含 chunked 时有意义;TE 不含 chunked 却给 chunked:
	// (哪怕是空 mapping) -> 硬错(防笔误)。
	hasChunked := slices.Contains(teEff, CodingChunked)
	if chunked != nil && !hasChunked {
		return fmt.Errorf("chunked 子结构仅在 transfer_encoding 含 chunked 时有效(当前 transfer_encoding 不含 chunked)")
	}
	if chunked != nil {
		if chunked.Size < 0 {
			return fmt.Errorf("chunked.size 不可为负(得到 %d);整段一块用 0/缺省,切多块用 >0", chunked.Size)
		}
		if chunked.Size > maxChunkedSize {
			return fmt.Errorf("chunked.size %d 超过上限 %d", chunked.Size, maxChunkedSize)
		}
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
