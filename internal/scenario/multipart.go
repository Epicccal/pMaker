package scenario

import (
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/util/cte"
)

// 本文件实现 MIME multipart body(RFC 2046)的「合法基线」校验,对齐 SMTP/FTP/Telnet
// 校验风格:只判合法性,绝不改变序列化行为(序列化在 builder/multipart.go)。无法用结构化
// multipart 表达的畸形(缺终止符、嵌套 multipart、preamble/epilogue 等)走父层的原始字节兜底:
// eml_data 走 raw/raw_hex,http_request/http_response 走 payload/payload_hex。
//
// multipart 不是独立层,而是嵌在 http_request/http_response/eml_data 内的子字段;故校验由
// 各层的 validateLayer case 调 validateMultipart,父级互斥(eml_data 的 body/raw/raw_hex、
// http 的 body)也由各层 case 负责。

// validateMultipart 校验 MultipartBody 的合法性:
//   - parts 至少 1 个;
//   - boundary 非空时须符合 RFC 2046 §5.1.1(长度 1–70、bchars 字符集、空格不结尾);
//     空 boundary = 用默认值(合规,跳过校验);
//   - 每 part:body/body_hex/nested 三选一互斥;body_hex 须合法 0x hex;encoding ∈ RFC 2045 §6 CTE;
//   - 递归校验 nested multipart;
//   - 全局 boundary 冲突检查:父子 boundary 不能相同。
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

	// 全局 boundary 冲突检查
	if err := validateBoundaryConflict(m); err != nil {
		return err
	}

	return nil
}

// validateMultipartPart 校验单个 part:body/body_hex/nested 三选一互斥、body_hex 合法、encoding 枚举、递归校验 nested。
func validateMultipartPart(i int, p *MultipartPart) error {
	// 1. body/body_hex/nested 三选一互斥
	hasBody := p.Body != "" || p.BodyHex != ""
	if hasBody && p.Nested != nil {
		return fmt.Errorf("multipart.parts[%d]: body/body_hex 与 nested 不可同设(nested 本身即 part body)", i)
	}
	if !hasBody && p.Nested == nil {
		return fmt.Errorf("multipart.parts[%d]: body/body_hex/nested 至少一个(空 part 无意义)", i)
	}

	// 2. body/body_hex 原有互斥逻辑
	if p.Body != "" && p.BodyHex != "" {
		return fmt.Errorf("multipart.parts[%d]: body 与 body_hex 只能配置一个", i)
	}

	// 3. body_hex 合法性
	if p.BodyHex != "" {
		if _, err := ParsePayloadHex(p.BodyHex); err != nil {
			return fmt.Errorf("multipart.parts[%d].body_hex: %w", i, err)
		}
	}

	// 4. encoding 枚举校验
	switch p.Encoding {
	case "", "none", "7bit", "8bit", "binary", "base64", "quoted-printable":
	default:
		return fmt.Errorf("multipart.parts[%d].encoding 只能是 none/7bit/8bit/binary/base64/quoted-printable,得到 %q", i, p.Encoding)
	}

	// 5. 递归校验嵌套 multipart
	if p.Nested != nil {
		if err := validateMultipart(p.Nested); err != nil {
			return fmt.Errorf("multipart.parts[%d].nested: %w", i, err)
		}
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

// MultipartBoundary 返回 multipart 使用的实际 boundary(空则按深度取确定性默认值)。
// depth 从 0 开始递增,保证嵌套层级的默认 boundary 互不相同(父子同值会导致解析端无法区分层级)。
// builder 与一致性告警共用,确保「Content-Type 头里的 boundary」与「实际分界符」比对一致。
func MultipartBoundary(m *MultipartBody, depth int) string {
	if m.Boundary != "" {
		return m.Boundary
	}
	return fmt.Sprintf("----=_pMaker_%04d", depth+1)
}

// ApplyTransferEncoding 对任意字节应用 CTE 编码(RFC 2045 §6)。
// builder 与 scenario 共享,对叶 part body 与嵌套 multipart 整体统一编码。
//   - ""/none 与 7bit/8bit/binary:恒等透传(仅声明字节性质);
//   - base64:RFC 2045 每 76 字符折行(\r\n 分隔),见 util/cte;
//   - quoted-printable:RFC 2045 QP 编码,见 util/cte。
func ApplyTransferEncoding(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "", "none", "7bit", "8bit", "binary":
		return data, nil
	case "base64":
		return cte.Base64Fold(data), nil
	case "quoted-printable":
		return cte.QPEncode(data)
	}
	// 校验已拦截非法 encoding,兜底原样返回。
	return data, nil
}

// EncodeMultipartPart 取单个 part 的编码后字节:body(或 ParsePayloadHex(body_hex))
// 按 encoding 做传输编码。builder.serializeMultipart 与 CheckMultipartConsistency 的
// boundary 碰撞检查共用本函数,按构造保证「检查看到的字节」与「实际落盘字节」一致,
// 消除两处实现漂移的可能。纯函数。
func EncodeMultipartPart(p *MultipartPart) ([]byte, error) {
	var body []byte
	if p.Body != "" {
		body = []byte(p.Body)
	} else if p.BodyHex != "" {
		b, err := ParsePayloadHex(p.BodyHex)
		if err != nil {
			return nil, err
		}
		body = b
	}
	return ApplyTransferEncoding(body, p.Encoding)
}

// validateBoundaryConflict 检查整个 multipart 树的 boundary 冲突:
// 每层 boundary 须互不相同,父子 boundary 重复会导致解析端无法区分层级。
func validateBoundaryConflict(m *MultipartBody) error {
	boundaries := make(map[string][]string) // boundary -> paths
	collectBoundaries(m, "", 0, boundaries)

	for b, paths := range boundaries {
		if len(paths) > 1 {
			return fmt.Errorf("boundary %q 在多个层级重复使用(%s);父子 multipart 的 boundary 须互不相同,请更换",
				b, strings.Join(paths, ", "))
		}
	}
	return nil
}

// collectBoundaries 递归收集 multipart 树中所有 boundary 及其路径。
func collectBoundaries(m *MultipartBody, path string, depth int, acc map[string][]string) {
	b := MultipartBoundary(m, depth)
	if path == "" {
		path = "multipart"
	}
	acc[b] = append(acc[b], path)

	for i, p := range m.Parts {
		if p.Nested != nil {
			nestedPath := fmt.Sprintf("%s.parts[%d].nested", path, i)
			collectBoundaries(p.Nested, nestedPath, depth+1, acc)
		}
	}
}
