package builder

import (
	"fmt"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件实现 IMAP4rev2(RFC 9051)客户端命令 / 服务器响应的序列化,产出 TCP payload 字节。
// IMAP 无 gopacket layer(同 HTTP/FTP/TELNET/SMTP/POP3),自序列化为 gopacket.Payload;
// 不碰 IP next-proto 串接、无独立 checksum(TCP 构造器负责)。
//
// IMAP 是「行 + 长度前缀混合定界」(RFC 9051 §2.2):literal 嵌在命令/响应中间,
// 前后都有文本。序列化的核心是 imapLiteralBytes:算 n、按 binary 选 {n}/~{n}、按 sync
// 决定是否加 +、按 emit 决定输出前缀/数据/两者。
//
// builder 端不做二次判别、不做形态推断:三形式由校验保证互斥,状态组/数据组由校验
// 保证互斥(决策 7),binary+sync:false 由校验硬错拦截(决策 8)。序列化层只按字段产出字节。

// serializeIMAPReq 把一条 IMAP 客户端输入序列化为 TCP payload 字节。三形式(校验保证互斥):
//   - 形式 C(literal.emit=data):仅 literal 八位组 + 命令终止 CRLF
//     (CRLF 是命令终止符,由本函数末尾追加;同步 literal 第①段已结束于 {n}\r\n,
//     命令的终止 CRLF 落到第③段末尾)。
//   - 形式 B(line):line + CRLF(DONE / SASL base64 续行 / 取消 literal 的 *)。
//   - 形式 A(tag+command):tag + SP + command [+ SP + args] [+ SP + literal] + CRLF。
//     literal 前缀/全量前自动插一个 SP(literal 是命令的一个参数,与前一 token 间必须 SP 分隔,
//     覆盖 `LOGIN {10}` 这类 literal 为首个参数的合法形态);emit=prefix 时 CRLF 由 literal
//     前缀自带({n}\r\n),不再追加命令终止 CRLF;emit=full 时 literal 末尾是 octets,追加 CRLF。
func serializeIMAPReq(f *scenario.IMAPRequestFields) ([]byte, error) {
	// 形式 C:literal.emit=data —— 独立八位组消息 + 命令终止 CRLF。
	if f.Literal != nil && f.Literal.Emit == "data" {
		content, err := imapLiteralContent(f.Literal)
		if err != nil {
			return nil, err
		}
		return append(content, '\r', '\n'), nil
	}
	// 形式 B:裸行 line + CRLF。
	if f.Line != "" {
		return []byte(f.Line + "\r\n"), nil
	}
	// 形式 A:命令行 tag SP command [SP args] [SP literal] CRLF。
	var b []byte
	b = append(b, f.Tag...)
	b = append(b, ' ')
	b = append(b, f.Command...)
	if f.Args != "" {
		b = append(b, ' ')
		b = append(b, f.Args...)
	}
	if f.Literal != nil {
		// literal 前缀/全量前自动插 SP(与 args 是否存在无关)。
		b = append(b, ' ')
		lb, err := imapLiteralBytes(f.Literal)
		if err != nil {
			return nil, err
		}
		b = append(b, lb...)
		if f.Literal.Emit == "prefix" {
			// emit=prefix:CRLF 由 literal 前缀({n}\r\n)自带,不再追加命令终止 CRLF。
			return b, nil
		}
		// emit=full:literal 末尾是 octets,追加命令终止 CRLF。
		return append(b, '\r', '\n'), nil
	}
	return append(b, '\r', '\n'), nil
}

// serializeIMAPResp 把一条 IMAP 服务器响应序列化为 TCP payload 字节。tag 三态定型:
//   - 前缀:"* "(untagged)/ "+ "(continuation)/ "tag SP"(tagged)。
//   - continuation(tag="+"):"+ " + text + CRLF(continue-req = "+" SP (resp-text / base64) CRLF)。
//   - 状态形式(status 非空):status [+ " [" code "]"] [+ SP text] + CRLF。
//   - 数据形式(data 非空):data [+ literal] [+ tail] + CRLF。
//
// 两个分支由校验保证互斥(决策 7):status 非空即状态形式,data 非空即数据形式,
// 校验已排除两者同现与「状态响应误写进 data」的形态。builder 不二次推断。
func serializeIMAPResp(f *scenario.IMAPResponseFields) ([]byte, error) {
	var b []byte
	// 1. 前缀。
	switch f.Tag {
	case "*":
		b = append(b, "* "...)
	case "+":
		b = append(b, "+ "...)
	default:
		b = append(b, f.Tag...)
		b = append(b, ' ')
	}
	// 2. continuation("+"):仅 text。
	if f.Tag == "+" {
		b = append(b, f.Text...)
		return append(b, '\r', '\n'), nil
	}
	// 3. 状态形式(status 非空):status ["[" code "]"] [SP text] CRLF。
	if f.Status != "" {
		b = append(b, f.Status...)
		if f.Code != "" {
			b = append(b, " ["...)
			b = append(b, f.Code...)
			b = append(b, ']')
		}
		if f.Text != "" {
			b = append(b, ' ')
			b = append(b, f.Text...)
		}
		return append(b, '\r', '\n'), nil
	}
	// 4. 数据形式(data 非空):data [literal] [tail] CRLF。
	b = append(b, f.Data...)
	if f.Literal != nil {
		lb, err := imapLiteralBytes(f.Literal)
		if err != nil {
			return nil, err
		}
		b = append(b, lb...)
	}
	b = append(b, f.Tail...)
	return append(b, '\r', '\n'), nil
}

// imapLiteralBytes 是 literal 的共用序列化助手(RFC 9051 §4.3):
//   - 算 n:octets 非 nil 则原样用(关闭自动计算,构造「计数撒谎」畸形),否则 len(content);
//   - 按 binary 选 {n} / ~{n}(literal8,BINARY);按 sync 决定是否加 +(非同步 {n+});
//   - 按 emit 决定输出:full(缺省)= {n}\r\n + 数据;prefix = 仅 {n}\r\n;data = 仅数据。
//
// binary 与 sync 不得正交组合(决策 8):literal8 无 {n+} 非同步形式,~{n+} 不是已定义 token。
// 此处不重复判别 —— 校验是唯一闸门(与「校验已排除的形态,builder 不二次推断」一致)。
func imapLiteralBytes(f *scenario.IMAPLiteral) ([]byte, error) {
	content, err := imapLiteralContent(f)
	if err != nil {
		return nil, err
	}
	n := len(content)
	if f.Octets != nil {
		n = *f.Octets
	}
	sync := f.Sync == nil || *f.Sync
	var prefix string
	switch {
	case f.Binary:
		prefix = fmt.Sprintf("~{%d}", n)
	case sync:
		prefix = fmt.Sprintf("{%d}", n)
	default:
		prefix = fmt.Sprintf("{%d+}", n)
	}
	emit := f.Emit
	if emit == "" {
		emit = "full"
	}
	if emit == "data" {
		return content, nil
	}
	b := []byte(prefix + "\r\n")
	if emit == "full" {
		b = append(b, content...)
	}
	return b, nil
}

// imapLiteralContent 取 literal 的八位组内容(eml / data / data_hex 三选一,校验保证互斥):
//   - eml:复用 SerializeEMLData 取纯 RFC 5322 内容(无 dot-stuffing、无终止符 ——
//     这正是 eml_data 注释里为 IMAP 预留的路径,IMAP 用 {n}\r\n 前缀包装);
//   - data:字面字节;
//   - data_hex:十六进制解码(二进制,配 binary: true)。
func imapLiteralContent(f *scenario.IMAPLiteral) ([]byte, error) {
	if f.EML != nil {
		return SerializeEMLData(f.EML)
	}
	if f.DataHex != "" {
		return scenario.ParsePayloadHex(f.DataHex)
	}
	return []byte(f.Data), nil
}
