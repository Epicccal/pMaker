// Package cte 实现 RFC 2045 定义的内容传输编码（Content-Transfer-Encoding）原语：
// base64 折行编码与 quoted-printable 编码。
//
// 这两种编码是 MIME multipart（RFC 2046）part body 的传输编码，同时也适用于
// EML 正文及其他需要 RFC 2045 CTE 的场景，因此从具体的协议 builder 中抽离，
// 供多个接入层复用。
//
// 注意：none / 7bit / 8bit / binary 是恒等编码（identity），原样透传字节，
// 不需要专门的函数——调用方直接使用原始字节即可。
package cte

import (
	"bytes"
	"encoding/base64"
	"mime/quotedprintable"
	"strings"
)

// Base64Fold 用 StdEncoding 对 body 做 base64 编码，并按 RFC 2045 §6.8 每 76
// 字符折行（\r\n 分隔）。输出确定性：同输入 → 同输出。
// 结尾不额外追加 CRLF，由调用方按上下文决定是否补充。
func Base64Fold(body []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(body)
	if len(enc) <= 76 {
		return []byte(enc)
	}
	var b strings.Builder
	b.Grow(len(enc) + (len(enc)/76)*2)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(enc[i:end])
	}
	return []byte(b.String())
}

// QPEncode 用 quoted-printable 对 body 做编码（RFC 2045 §6.7）。
func QPEncode(body []byte) ([]byte, error) {
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
