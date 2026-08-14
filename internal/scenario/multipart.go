package scenario

import "fmt"

// 本文件实现 MIME multipart body(RFC 2046)的「合法基线」校验,对齐 SMTP/FTP/Telnet
// 校验风格:只判合法性,绝不改变序列化行为(序列化在 builder/multipart.go)。无法用结构化
// multipart 表达的畸形(缺终止符、嵌套 multipart、preamble/epilogue 等)走父层的原始字节兜底:
// eml_data 走 raw/raw_hex,http_request/http_response 走 payload/payload_hex。
//
// multipart 不是独立层,而是嵌在 http_request/http_response/eml_data 内的子字段;故校验由
// 各层的 validateLayer case 调 validateMultipart,父级互斥(eml_data 的 body/raw/raw_hex、
// http 的 body)也由各层 case 负责。

// multipartDefaultBoundary 是 boundary 为空时使用的确定性默认分界符(RFC 2046 合法 bchars)。
// 固定常量保证同输入 → 逐字节相同 pcap(确定性),且足够长以降低与 part 内容碰撞的概率。
const multipartDefaultBoundary = "----=_pMaker_0001"

// validateMultipart 校验 MultipartBody 的合法性:
//   - parts 至少 1 个;
//   - boundary 非空时须符合 RFC 2046 §5.1.1(长度 1–70、bchars 字符集、空格不结尾);
//     空 boundary = 用默认值(合规,跳过校验);
//   - 每 part:body/body_hex 互斥;body_hex 须合法 0x hex;encoding ∈ RFC 2045 §6 CTE
//     (none/7bit/8bit/binary 为恒等编码透传,base64/quoted-printable 为真变换)。
func validateMultipart(m *MultipartBody) error {
	if m == nil {
		return nil
	}
	if len(m.Parts) == 0 {
		return fmt.Errorf("multipart.parts 至少需要 1 个 part(空 multipart 无意义;构造畸形请用父层的 raw/raw_hex 或 payload/payload_hex)")
	}
	if m.Boundary != "" {
		if err := validateBoundary(m.Boundary); err != nil {
			return err
		}
	}
	for i, p := range m.Parts {
		if err := validateMultipartPart(i, &p); err != nil {
			return err
		}
	}
	return nil
}

// validateMultipartPart 校验单个 part:body/body_hex 互斥、body_hex 合法、encoding 枚举。
func validateMultipartPart(i int, p *MultipartPart) error {
	if p.Body != "" && p.BodyHex != "" {
		return fmt.Errorf("multipart.parts[%d]: body 与 body_hex 只能配置一个", i)
	}
	if p.BodyHex != "" {
		if _, err := ParsePayloadHex(p.BodyHex); err != nil {
			return fmt.Errorf("multipart.parts[%d].body_hex: %w", i, err)
		}
	}
	switch p.Encoding {
	case "", "none", "7bit", "8bit", "binary", "base64", "quoted-printable":
	default:
		return fmt.Errorf("multipart.parts[%d].encoding 只能是 none/7bit/8bit/binary/base64/quoted-printable,得到 %q", i, p.Encoding)
	}
	return nil
}

// validateBoundary 校验 boundary 符合 RFC 2046 §5.1.1:
//
//	bcharsnospace = DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":" / "=" / "?"
//	bchars        = bcharsnospace / " "
//	boundary      = 0*69(bchars) bcharsnospace   ; 长度 1–70,末字符不得为空格
//
// 不合法 → 报错并引导走父层原始字节兜底(eml_data 走 raw/raw_hex,http 走 payload/payload_hex)。
func validateBoundary(b string) error {
	if len(b) < 1 || len(b) > 70 {
		return fmt.Errorf("multipart.boundary 长度须 1-70,得到 %d(非标 boundary 请用父层的 raw/raw_hex 或 payload/payload_hex 手拼)", len(b))
	}
	for i := 0; i < len(b); i++ {
		if !isBchar(b[i], i == len(b)-1) {
			return fmt.Errorf("multipart.boundary %q 含非法字符(第 %d 位);RFC 2046 bchars 限 0-9A-Za-z'()+_,.-/:=? 与空格(空格不得结尾),非标 boundary 请用父层的 raw/raw_hex 或 payload/payload_hex 手拼", b, i+1)
		}
	}
	return nil
}

// isBchar 报告 c 是否为 RFC 2046 bchars 字符。isLast 表示是否为末字符:末字符不得为空格。
func isBchar(c byte, isLast bool) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c == '\'' || c == '(' || c == ')' || c == '+' || c == '_' ||
		c == ',' || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' || c == '?':
		return true
	case c == ' ' && !isLast:
		return true
	}
	return false
}

// MultipartBoundary 返回 multipart 使用的实际 boundary(空则取确定性默认值)。
// builder 与一致性告警共用,确保「Content-Type 头里的 boundary」与「实际分界符」比对一致。
func MultipartBoundary(m *MultipartBody) string {
	if m.Boundary != "" {
		return m.Boundary
	}
	return multipartDefaultBoundary
}
