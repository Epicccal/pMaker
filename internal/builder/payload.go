package builder

import (
	"fmt"

	"github.com/Epicccal/pMaker/internal/scenario"
)

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
