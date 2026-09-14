package builder

import (
	"bytes"
	"fmt"

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
// 每 part body 经 scenario.EncodeMultipartPart 取字节并按 encoding 编码(共享实现,
// 见 scenario/multipart.go):
//
// 不做 CRLF 归一化:body(含 @file 注入的文本/二进制)与 body_hex 均保留原始字节。
// @file 可注入二进制附件(图片、压缩包),对二进制做裸 \n→\r\n 归一化会破坏文件字节,
// 故把换行正确性交给用户(与 HTTP body 现状一致)。构造非标换行的畸形 part 走 raw/payload_hex 兜底。
//
// boundary 碰撞告警(RFC 2046 §5.1.1:分界符须独占一行)不在本文件:检查在
// scenario.CheckMultipartConsistency(编码实现共享 EncodeMultipartPart),经
// scenario.Warnings 回流 CLI stderr / MCP 结构化 warnings。

// serializeMultipart 把 MultipartBody 序列化为整段 multipart 字节(含终止 boundary 行)。
// 纯函数:无副作用。
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
		// part body:取字节 → 编码(与 scenario 碰撞检查共享同一实现)。
		encoded, err := scenario.EncodeMultipartPart(p)
		if err != nil {
			return nil, fmt.Errorf("multipart.parts[%d]: %w", i, err)
		}
		b.Write(encoded)
		// part body 末尾补 \r\n 再写下一个分界符(RFC 2046:boundary 前须有 CRLF)。
		b.WriteString("\r\n")
	}
	// 终止 boundary 行(--boundary--\r\n)。
	b.WriteString(delim)
	b.WriteString("--\r\n")
	return b.Bytes(), nil
}
