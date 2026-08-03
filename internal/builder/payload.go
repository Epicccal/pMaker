package builder

import (
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeTextReply 是 FTP/SMTP 共用的文本行响应序列化(多行续行字节级相同)。
// RFC 959 §4.1.3 与 RFC 5321 §4.2.1 的续行格式一致:非末行 "code-text\r\n"、
// 末行 "code final\r\n"。不跳过空元素——空文本行是协议合法的(RFC 959 末行
// "optionally some text",续行 text 无最小长度要求),如实输出:
//   - 非末行空元素 → "code-\r\n";
//   - 末行空元素 → "code \r\n"(%d %s 格式,空 text 留一个空格)。
//
// message 与 lines 互斥:lines 非空走多行;否则走单行(message 为空则 "code\r\n")。
func serializeTextReply(code int, message string, lines []string) []byte {
	var b strings.Builder
	if len(lines) > 0 {
		for i, line := range lines {
			if i == len(lines)-1 {
				fmt.Fprintf(&b, "%d %s\r\n", code, line)
			} else {
				fmt.Fprintf(&b, "%d-%s\r\n", code, line)
			}
		}
		return []byte(b.String())
	}
	if message == "" {
		fmt.Fprintf(&b, "%d\r\n", code)
	} else {
		fmt.Fprintf(&b, "%d %s\r\n", code, message)
	}
	return []byte(b.String())
}

// PayloadBytes 返回一个 payload 生产层序列化后的字节。
// 供 flow 展开器取长度并按 MSS 切段(与 serializeStack 复用同一套序列化)。
func PayloadBytes(l scenario.Layer) ([]byte, error) {
	switch f := l.Fields.(type) {
	case *scenario.HTTPReqFields:
		return serializeHTTPReq(f), nil
	case *scenario.HTTPRespFields:
		return serializeHTTPResp(f), nil
	case *scenario.FTPRequestFields:
		return serializeFTPReq(f), nil
	case *scenario.FTPResponseFields:
		return serializeFTPResp(f), nil
	case *scenario.TelnetFields:
		return serializeTelnet(f)
	case *scenario.PayloadFields:
		return payloadBytes(f)
	case scenario.PayloadHex:
		return scenario.ParsePayloadHex(string(f))
	default:
		return nil, fmt.Errorf("%q 不是 payload 生产层", l.Type)
	}
}

func payloadBytes(f *scenario.PayloadFields) ([]byte, error) {
	if f.PayloadHex != "" {
		return scenario.ParsePayloadHex(f.PayloadHex)
	}
	return []byte(f.Payload), nil
}
