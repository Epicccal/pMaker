package builder

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// PayloadBytes 返回一个 payload 生产层序列化后的字节。
// 供 flow 展开器取长度并按 MSS 切段(与 buildPacket 内的处理复用同一套序列化)。
func PayloadBytes(l scenario.Layer) ([]byte, error) {
	switch f := l.Fields.(type) {
	case *scenario.HTTPReqFields:
		return serializeHTTPReq(f), nil
	case *scenario.HTTPRespFields:
		return serializeHTTPResp(f), nil
	case *scenario.PayloadFields:
		return payloadBytes(f)
	case scenario.RawHex:
		return rawHexBytes(f)
	default:
		return nil, fmt.Errorf("%q 不是 payload 生产层", l.Type)
	}
}

func payloadBytes(f *scenario.PayloadFields) ([]byte, error) {
	if f.Hex != "" {
		return hex.DecodeString(strings.ReplaceAll(f.Hex, " ", ""))
	}
	return []byte(f.Text), nil
}

func rawHexBytes(h scenario.RawHex) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(string(h), " ", ""))
}
