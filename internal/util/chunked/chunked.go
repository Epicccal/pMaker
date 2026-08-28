// Package chunked 实现 RFC 9112 §7.1 的 HTTP/1.1 chunked transfer-encoding 成帧。
//
// chunked 是「接收端如何确定 body 边界」这一问题在 HTTP/1.1 系协议中的答案，
// 与 dotframe 的 <CRLF>.<CRLF> 终止符（SMTP/POP3）属于同类机制。除 HTTP/1.1 外，
// ICAP（RFC 3507）的封装体亦强制使用 chunked 成帧。
package chunked

import (
	"bytes"
	"strconv"
)

// Frame 把 body 按 size 切块做 chunked transfer-encoding 成帧（RFC 9112 §7.1）。
//   - size==0：整个 body 作为一个 chunk（契约行为）；
//   - size>0：按 size 切分，每块长自动十六进制；
//   - 始终追加合法终止块 "0\r\n\r\n"。
//
// 块格式："%x\r\n" + data + "\r\n"（块长十六进制）。
// 空 body 合规输出 "0\r\n\r\n"（仅终止块）。
//
// size<0 归入「整段一块」分支，仅作 defense-in-depth 兜底（调用方应在校验阶段
// 拦截负数），非契约行为，不应被测试当作等价语义固化。
func Frame(b []byte, size int) []byte {
	var out bytes.Buffer
	if size <= 0 {
		// 整段一块。空 body 不写数据块（只留终止块，合规输出 "0\r\n\r\n"）。
		if len(b) > 0 {
			writeChunk(&out, b)
		}
	} else {
		for i := 0; i < len(b); i += size {
			end := i + size
			if end > len(b) {
				end = len(b)
			}
			writeChunk(&out, b[i:end])
		}
	}
	// 终止块。
	out.WriteString("0\r\n\r\n")
	return out.Bytes()
}

// writeChunk 写一个 chunk："%x\r\n" + data + "\r\n"。
func writeChunk(out *bytes.Buffer, data []byte) {
	out.WriteString(strconv.FormatInt(int64(len(data)), 16))
	out.WriteString("\r\n")
	out.Write(data)
	out.WriteString("\r\n")
}
