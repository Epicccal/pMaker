package builder

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"mime/quotedprintable"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件实现 MIME multipart body(RFC 2046)的序列化,作 HTTP 或 EML 的 body。
// 手工拼装(对齐项目里 HTTP/EML/SMTP 手写序列化的透明风格,不引 mime/multipart,
// 便于后续加畸形开关)。multipart 不是独立层,由 http/eml builder 嵌套调用。
//
// 拼装格式(RFC 2046 §5.1.1):
//
//	--boundary\r\n
//	{part1 headers}\r\n
//	\r\n
//	{part1 encoded body}\r\n
//	--boundary\r\n
//	{part2 headers}\r\n
//	\r\n
//	{part2 encoded body}\r\n
//	--boundary--\r\n
//
// 每 part body 先取字节(body 或 ParsePayloadHex(body_hex)),再按 encoding 编码:
//   - base64:encoding/base64.StdEncoding,按 RFC 2045 每 76 字符折行(\r\n 分隔,确定性);
//   - quoted-printable:mime/quotedprintable;
//   - none/7bit/8bit/binary:RFC 2045 §6 恒等编码,原样透传(7bit/8bit/binary 仅声明 body 字节性质,
//     不做任何变换,与 none 行为一致)。
//
// 不做 CRLF 归一化:body(含 @file 注入的文本/二进制)与 body_hex 均保留原始字节。
// @file 可注入二进制附件(图片、压缩包),对二进制做裸 \n→\r\n 归一化会破坏文件字节,
// 故把换行正确性交给用户(与 HTTP body 现状一致)。构造非标换行的畸形 part 走 raw/payload_hex 兜底。
//
// boundary 碰撞告警(RFC 2046 §5.1.1:分界符须独占一行):每个 part 编码后字节逐行扫描,
// 若某行 TrimRight(空白/CRLF) == "--"+boundary → slog.Warn(非硬错)。按行匹配而非朴素子串
// 包含,避免行内偶现子串误报。命中时引导用户换更长的 boundary。

// serializeMultipart 把 MultipartBody 序列化为整段 multipart 字节(含终止 boundary 行)。
// 纯函数:无副作用(除 boundary 碰撞告警走 slog.Warn)。
func serializeMultipart(m *scenario.MultipartBody) ([]byte, error) {
	boundary := scenario.MultipartBoundary(m)
	delim := "--" + boundary

	var b bytes.Buffer
	for i := range m.Parts {
		p := &m.Parts[i]
		// 分界符行。
		b.WriteString(delim)
		b.WriteString("\r\n")
		// part 头(按 HeaderMap 原序输出)。
		p.Headers.Range(func(k, v string) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		})
		// 头体分隔空行。
		b.WriteString("\r\n")
		// part body:取字节 → 编码。
		body, err := partBodyBytes(p)
		if err != nil {
			return nil, fmt.Errorf("multipart.parts[%d]: %w", i, err)
		}
		encoded, err := encodePartBody(body, p.Encoding)
		if err != nil {
			return nil, fmt.Errorf("multipart.parts[%d].encoding: %w", i, err)
		}
		b.Write(encoded)
		// part body 末尾补 \r\n 再写下一个分界符(RFC 2046:boundary 前须有 CRLF)。
		b.WriteString("\r\n")

		// boundary 碰撞告警:扫描编码后字节,某行独占 == "--"+boundary 则告警。
		warnBoundaryCollision(boundary, encoded, i)
	}
	// 终止 boundary 行(--boundary--\r\n)。
	b.WriteString(delim)
	b.WriteString("--\r\n")
	return b.Bytes(), nil
}

// partBodyBytes 取 part 的原始 body 字节:body 优先,其次 ParsePayloadHex(body_hex)。
// 校验已保证 body/body_hex 互斥,此处不再重复判定。
func partBodyBytes(p *scenario.MultipartPart) ([]byte, error) {
	if p.Body != "" {
		return []byte(p.Body), nil
	}
	if p.BodyHex != "" {
		return scenario.ParsePayloadHex(p.BodyHex)
	}
	return nil, nil
}

// encodePartBody 按 encoding 对原始 body 字节做传输编码。
//   - "" / "none":原样返回;
//   - "7bit" / "8bit" / "binary":RFC 2045 §6 恒等编码(identity),声明 body 字节性质、
//     不做任何变换,原样返回(对齐 encoding: none 的行为);
//   - "base64":RFC 2045 每 76 字符折行(\r\n 分隔);
//   - "quoted-printable":mime/quotedprintable 编码。
func encodePartBody(body []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "", "none", "7bit", "8bit", "binary":
		return body, nil
	case "base64":
		return base64Fold(body), nil
	case "quoted-printable":
		return qpEncode(body)
	}
	// 校验已拦截非法 encoding,兜底原样返回。
	return body, nil
}

// base64Fold 用 StdEncoding 编码 body,并按 RFC 2045 每 76 字符折行(\r\n 分隔)。
// 输出确定性(同输入 → 同输出),结尾不额外加 CRLF(由调用方在 part body 末尾统一补)。
func base64Fold(body []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(body)
	if len(enc) <= 76 {
		return []byte(enc)
	}
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(enc[i:end])
	}
	return []byte(b.String())
}

// qpEncode 用 quoted-printable 编码 body(RFC 2045)。
func qpEncode(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write(body); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// warnBoundaryCollision 扫描编码后 part body,若某行(去尾空白/CRLF)独占 "--"+boundary,
// 产 slog.Warn(RFC 2046 §5.1.1:分界符须独占一行,解析端会误判切分)。非硬错,畸形/故意的
// 边界碰撞用例可继续。@file 注入附件(内容不可预知)时尤其隐蔽。
func warnBoundaryCollision(boundary string, encoded []byte, partIdx int) {
	delim := "--" + boundary
	for _, line := range bytes.Split(encoded, []byte("\n")) {
		if strings.TrimRight(string(line), " \t\r\n") == delim {
			slog.Warn("multipart: part body 内出现独占一行的 boundary 分界符",
				"part", partIdx, "boundary", boundary,
				"hint", "解析端可能误判切分 multipart;请更换更长的 boundary(默认 boundary 碰撞概率极低)")
			return
		}
	}
}
