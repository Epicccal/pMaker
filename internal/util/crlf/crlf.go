// Package crlf 实现行结束符归一化原语：把字符串里的裸 \n（前一字节不是 \r）
// 归一化为 \r\n。
//
// 这是 RFC 5322 §2.1（邮件正文行须以 CRLF 结束）等规范的结构化内容序列化基础：
// 用户在 YAML 里写 body（尤其用 `|` 块标量，YAML 默认产出 \n）常带入裸 \n，
// 结构化模式帮用户抹平这个落差，产出合规的 \r\n；原始模式不归一化（保留精确字节，
// 构造非标换行畸形）。原语本身不含模式判定，调用方决定是否归一化。
//
// 已是 \r\n 的不动；lone \r 不动（老 Mac 换行，结构化 body 里不预期出现，
// 归一化 lone \r 会改变二进制语义，故不碰）。
package crlf

import "strings"

// NormalizeCRLF 把字符串里的裸 \n（前一字节不是 \r）归一化为 \r\n。
// 不含 \n 时原样返回（避免无谓分配）。
func NormalizeCRLF(s string) string {
	if !strings.ContainsRune(s, '\n') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' && (i == 0 || s[i-1] != '\r') {
			b.WriteByte('\r')
		}
		b.WriteByte(c)
	}
	return b.String()
}
