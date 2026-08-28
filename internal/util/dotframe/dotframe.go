// Package dotframe 实现 RFC 5321 §4.5.2 / RFC 1939 §3 的 dot 成帧原语：
// dot-stuffing（透明性处理）与 dot-terminator（多行响应终止符）。
//
// 这两个原语是 SMTP、POP3 以及所有基于同一成帧规则的邮件传输协议的共同基础，
// 因此从具体的协议 builder 中抽离，供多个接入层复用。
//
// 用法示意：
//
//	// SMTP DATA / POP3 RETR 接入层：
//	framed := dotframe.AppendDotTerminator(dotframe.ApplyDotStuffing(content))
package dotframe

import "bytes"

// ApplyDotStuffing 对正文做 RFC 5321 §4.5.2 / RFC 1939 §3 的透明性处理：
// 每行行首为 '.' 的行前面加一个 '.'，无论该行是否只有 '.'。
// 按 \r\n 分行处理（保留 \r\n），首行特殊处理（无前导 \r\n）。
//
// 注意：raw 模式（不经 CRLF 归一化）的裸 \n 开头的 '.' 不会被 stuffing，
// 这是构造非标换行畸形的预期行为。
func ApplyDotStuffing(content []byte) []byte {
	out := make([]byte, 0, len(content)+8)
	atLineStart := true
	for i := 0; i < len(content); i++ {
		c := content[i]
		if atLineStart && c == '.' {
			out = append(out, '.')
		}
		out = append(out, c)
		// 更新行起始状态：遇到 \r\n 后下一字节为新行起点。
		if c == '\n' && i > 0 && content[i-1] == '\r' {
			atLineStart = true
		} else {
			atLineStart = false
		}
	}
	return out
}

// AppendDotTerminator 追加 RFC 5321 §4.5.2 / RFC 1939 §3 的终止符 <CRLF>.<CRLF>：
// 若正文以 \r\n 结尾，追加 ".\r\n"；否则追加 "\r\n.\r\n"。
//
// 须在 ApplyDotStuffing 之后调用。
func AppendDotTerminator(content []byte) []byte {
	if bytes.HasSuffix(content, []byte("\r\n")) {
		return append(content, '.', '\r', '\n')
	}
	return append(content, '\r', '\n', '.', '\r', '\n')
}
