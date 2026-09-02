package builder

import (
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/util/crlf"
	"github.com/Epicccal/pMaker/internal/util/dotframe"
)

// SerializeEMLData 把 RFC 5322 邮件内容序列化为 TCP payload 字节（**纯内容，不含成帧**）。
// 协议无关的内容层：成帧（dot-stuffing + <CRLF>.<CRLF> 终止符）是传输协议的职责，由接入层
// 强制（SMTP DATA / POP3 RETR 的接入层调用 dotframe.ApplyDotStuffing + AppendDotTerminator；
// IMAP FETCH 未来用长度前缀 {n}\r\n 包装），不在内容层暴露开关。缺 dot-stuffing / 缺终止符
// 等畸形走 payload/payload_hex 原始字节兜底。
//
// 两种模式（互斥，由校验保证）：
//   - 结构化模式（headers/body）：拼装 headers（按 YAML 声明顺序）+ 空行 + body；
//   - 原始模式（raw/raw_hex）：裸透传字节。
//
// 结构化模式空行处理：headers 与 body 之间无条件插空行 "\r\n"（头体分隔符）。
// body 为空但 headers 非空时（合规空体邮件），产出 headers + 空行
// （headers 末尾的 \r\n 即为空行）。结构化模式要求 headers 非空（校验保证），
// 无头邮件等畸形请走 raw/raw_hex。
//
// 纯函数：可在层栈独立调用（SMTP/POP3 接入层负责成帧），也可在 imap_response builder
// 中嵌套调用（IMAP 用长度前缀包装）。行结束符归一化（裸 \n → \r\n）由 internal/util/crlf
// 提供，与 scenario 包的 IMAP literal 一致性告警共用同一份原语，避免 scenario→builder
// 循环依赖下的重复实现漂移。导出以供跨包等价测试
// （internal/scenario/imap_consistency_test.go 断言 scenario 侧 IMAP literal octets 告警的
// 字节计数口径与本函数逐字节一致）。
func SerializeEMLData(f *scenario.EMLDataFields) ([]byte, error) {
	var content []byte

	// 1. 确定模式：raw/raw_hex 非空 → 原始模式；否则 → 结构化模式。
	if f.Raw != "" || f.RawHex != "" {
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
		// 3. 结构化模式拼装：headers 按 YAML 声明顺序 → "Key: Value\r\n" → 空行 "\r\n" → body。
		//    headers 为空时仍插空行；body 为空时 headers 末尾 \r\n 即空行，不重复插。
		//    body 写入前做 line-ending 归一化（裸 \n → \r\n），见 crlf.NormalizeCRLF。
		//    multipart 邮件:body 取自 serializeMultipart 的字节(取代字面 body);
		//    multipart 字节不再经归一化(part 内部已保留原始字节)。
		var b strings.Builder
		f.Headers.Range(func(k, v string) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		})
		b.WriteString("\r\n")
		if f.Multipart != nil {
			mp, err := serializeMultipart(f.Multipart)
			if err != nil {
				return nil, fmt.Errorf("multipart: %w", err)
			}
			b.Write(mp)
		} else {
			b.WriteString(crlf.NormalizeCRLF(f.Body))
		}
		content = []byte(b.String())
	}

	return content, nil
}

// serializeEMLDataFramed 把 eml_data standalone 层序列化为带成帧的完整 SMTP DATA 正文字节：
// SerializeEMLData（纯内容）→ dotframe.ApplyDotStuffing → dotframe.AppendDotTerminator。
// serializeStack 与 PayloadBytes 都调用此函数，确保两条路径字节一致（flow 展开器
// 按 PayloadBytes 的长度切段，不一致会导致静默的分段长度错误）。
func serializeEMLDataFramed(f *scenario.EMLDataFields) ([]byte, error) {
	b, err := SerializeEMLData(f)
	if err != nil {
		return nil, err
	}
	return dotframe.AppendDotTerminator(dotframe.ApplyDotStuffing(b)), nil
}
