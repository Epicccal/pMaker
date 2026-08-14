package scenario

import "fmt"

// 本文件实现 eml_data 层的字段组合校验（合法基线），对齐 SMTP/FTP/Telnet 校验风格：
// 只判合法性，绝不改变序列化行为（序列化在 builder/eml_data.go）。无法用结构化字段
// 表达的畸形正文（重复头、非标换行、二进制正文等）走 eml_data 的 raw/raw_hex。
//
// eml_data 命名反映协议无关性：RFC 5322 邮件内容（headers + body）是 SMTP/POP3/IMAP 的
// 共同核心，framing 由 dot_stuff/dot_terminate 开关控制，详见 EMLDataFields 文档。

// validateEMLDataFields 校验 eml_data 字段组合的合法性。
//   - 模式互斥：结构化（headers/body）与原始（raw/raw_hex）不可同设；
//   - 结构化模式要求 headers 非空（RFC 5322 §3.6 邮件必有头；body 可空＝合规空体邮件）；
//     无头邮件（headers 空）非法，构造无头/缺头等畸形请用 raw/raw_hex；
//   - raw 与 raw_hex 互斥；
//   - 至少一种模式有内容（全空报错）；
//   - raw_hex 须为合法 0x 前缀十六进制；
//   - dot_stuff / dot_terminate 须为 on/off（缺省 on）。
func validateEMLDataFields(f *EMLDataFields) error {
	// 1. 模式互斥检查:multipart 属结构化模式(与 headers 同侧),与 raw 互斥、与字面 body 互斥。
	hasStruct := f.Headers.Len() > 0 || f.Body != "" || f.Multipart != nil
	hasRaw := f.Raw != "" || f.RawHex != ""
	if hasStruct && hasRaw {
		return fmt.Errorf("headers/body/multipart 与 raw/raw_hex 不可同设（结构化模式与原始模式互斥）")
	}
	if !hasStruct && !hasRaw {
		return fmt.Errorf("需要 headers/body/multipart 或 raw/raw_hex（空 EML 内容无意义；构造畸形正文请用 raw 或 raw_hex）")
	}
	// 2. 结构化模式要求 headers 非空：RFC 5322 §3.6 邮件必有头（至少 Date/From）。
	//    body 可空（合规空体邮件）；multipart 邮件顶层 MIME 头仍必填。
	//    无头邮件非法,构造无头/缺头畸形请走 raw/raw_hex。重复头(如多个 Received)结构化模式已支持,无需走 raw。
	if hasStruct && f.Headers.Len() == 0 {
		return fmt.Errorf("结构化模式需要 headers 非空（RFC 5322 邮件必有头；构造无头/缺头等畸形正文请用 raw 或 raw_hex）")
	}
	// 3. multipart 与字面 body 互斥(multipart 本身即 body)。
	if f.Multipart != nil && f.Body != "" {
		return fmt.Errorf("multipart 与 body 不可同设（multipart 本身即为邮件正文）")
	}
	// 4. multipart 内部合法性(parts/boundary/encoding/body_hex)。
	if f.Multipart != nil {
		if err := validateMultipart(f.Multipart); err != nil {
			return err
		}
	}
	// 5. raw 与 raw_hex 互斥
	if f.Raw != "" && f.RawHex != "" {
		return fmt.Errorf("raw 与 raw_hex 只能配置一个")
	}
	// 6. raw_hex 合法性
	if f.RawHex != "" {
		if _, err := ParsePayloadHex(f.RawHex); err != nil {
			return err
		}
	}
	// 7. dot_stuff / dot_terminate 枚举校验（缺省 on）
	for _, v := range []struct{ name, val string }{
		{"dot_stuff", f.DotStuff},
		{"dot_terminate", f.DotTerminate},
	} {
		if v.val != "" && v.val != "on" && v.val != "off" {
			return fmt.Errorf("%s 只能是 on/off，得到 %q", v.name, v.val)
		}
	}
	return nil
}
