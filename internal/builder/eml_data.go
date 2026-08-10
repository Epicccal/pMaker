package builder

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeEMLData 把 RFC 5322 邮件内容序列化为 TCP payload 字节。协议无关：
// SMTP DATA（RFC 5321）与 POP3 RETR（RFC 1939）使用行框架（dot-stuffing + 终止符），
// IMAP FETCH（RFC 9051）使用长度前缀字面量（无 dot-stuffing/终止符），由开关适配。
//
// 两种模式（互斥，由校验保证）：
//   - 结构化模式（headers/body）：拼装 headers（字典序）+ 空行 + body，
//     按 dot_stuff 做行首 dot-stuffing，按 dot_terminate 追加终止符 <CRLF>.<CRLF>。
//   - 原始模式（raw/raw_hex）：裸透传字节，按 dot_stuff 决定是否 stuffing，
//     按 dot_terminate 决定是否追加终止符。
//
// dot-stuffing（RFC 5321 §4.5.2 / RFC 1939 §3）：正文每行行首为 '.' 的行前面加一个 '.'，
// 无论该行是否只有 '.'。终止符 <CRLF>.<CRLF> 是正文之后的独立追加，不参与 stuffing。
//
// 结构化模式空行处理：headers 为空但 body 非空时，仍插入空行（产出 "\r\n" + body），
// 即无头邮件（RFC 5322 不合规但可构造为畸形）。body 为空但 headers 非空时，产出
// headers + 空行（headers 末尾的 \r\n 即为空行）。
//
// 纯函数：可在层栈独立调用（SMTP/POP3），也可在 imap_response builder 中嵌套调用（IMAP）。
// IMAP builder 调用前应自动覆写 dot_stuff/dot_terminate 为 off（见设计文档 §3.4/§10.3）。
func serializeEMLData(f *scenario.EMLDataFields) ([]byte, error) {
	var content []byte

	// 1. 确定模式：raw/raw_hex 非空 → 原始模式；否则 → 结构化模式。
	if f.Raw != "" || f.RawHex != "" {
		// 2. 原始模式取字节（raw 或 ParsePayloadHex(raw_hex)）。
		if f.RawHex != "" {
			b, err := scenario.ParsePayloadHex(f.RawHex)
			if err != nil {
				return nil, fmt.Errorf("raw_hex: %w", err)
			}
			content = b
		} else {
			content = []byte(f.Raw)
		}
	} else {
		// 3. 结构化模式拼装：headers 字典序 → "Key: Value\r\n" → 空行 "\r\n" → body。
		//    headers 为空时仍插空行；body 为空时 headers 末尾 \r\n 即空行，不重复插。
		var b strings.Builder
		keys := make([]string, 0, len(f.Headers))
		for k := range f.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s: %s\r\n", k, f.Headers[k])
		}
		b.WriteString("\r\n")
		b.WriteString(f.Body)
		content = []byte(b.String())
	}

	// 4. dot_stuff 决策（auto 等同 on）。
	if f.DotStuff != "off" {
		content = dotStuff(content)
	}

	// 5. dot_terminate 决策（auto 等同 on）。
	if f.DotTerminate != "off" {
		// 终止符 <CRLF>.<CRLF>：若正文以 \r\n 结尾，追加 ".\r\n"；否则追加 "\r\n.\r\n"。
		if bytes.HasSuffix(content, []byte("\r\n")) {
			content = append(content, '.', '\r', '\n')
		} else {
			content = append(content, '\r', '\n', '.', '\r', '\n')
		}
	}

	return content, nil
}

// dotStuff 对正文做 RFC 5321 §4.5.2 / RFC 1939 §3 的透明性处理：
// 每行行首为 '.' 的行前面加一个 '.'，无论该行是否只有 '.'。
// 按 \r\n 分行处理（保留 \r\n），首行特殊处理（无前导 \r\n）。
// 只识别 \r\n 行边界，不兼容裸 \n（raw 模式下 \n 开头的 '.' 不做 stuffing，
// 这本身就是畸形用例，行为可接受）。
func dotStuff(content []byte) []byte {
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
