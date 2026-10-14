package builder

import (
	"fmt"

	"github.com/gopacket/gopacket"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// PayloadBytes 是 PayloadBytesIn 的无传输层版本(dns 不套 TCP 长度前缀)。
func PayloadBytes(l scenario.Layer) ([]byte, error) { return PayloadBytesIn(l, false) }

// PayloadBytesIn 返回一个 payload 生产层序列化后的字节。overTCP 表示由 TCP 承载,
// 须与 serializeStack 的就近传输层判据一致。
// 供 flow 展开器取长度并按 MSS 切段(与 serializeStack 复用同一套序列化)。
func PayloadBytesIn(l scenario.Layer, overTCP bool) ([]byte, error) {
	switch f := l.Fields.(type) {
	case *scenario.HTTPReqFields:
		return serializeHTTPReq(f)
	case *scenario.HTTPRespFields:
		return serializeHTTPResp(f)
	case *scenario.FTPRequestFields:
		return serializeFTPReq(f), nil
	case *scenario.FTPResponseFields:
		return serializeFTPResp(f), nil
	case *scenario.TelnetFields:
		return serializeTelnet(f)
	case *scenario.SMTPRequestFields:
		return serializeSMTPReq(f), nil
	case *scenario.SMTPResponseFields:
		return serializeSMTPResp(f), nil
	case *scenario.POP3RequestFields:
		return serializePOP3Req(f), nil
	case *scenario.POP3ResponseFields:
		b, err := serializePOP3Resp(f)
		if err != nil {
			return nil, fmt.Errorf("pop3_response: %w", err)
		}
		return b, nil
	case *scenario.IMAPRequestFields:
		b, err := serializeIMAPReq(f)
		if err != nil {
			return nil, fmt.Errorf("imap_request: %w", err)
		}
		return b, nil
	case *scenario.IMAPResponseFields:
		b, err := serializeIMAPResp(f)
		if err != nil {
			return nil, fmt.Errorf("imap_response: %w", err)
		}
		return b, nil
	case *scenario.EMLDataFields:
		b, err := serializeEMLDataFramed(f)
		if err != nil {
			return nil, fmt.Errorf("eml_data: %w", err)
		}
		return b, nil
	case *scenario.DNSFields:
		// FixLengths 必开:段计数与 RDLENGTH 由它补齐,关掉会产出全零计数的 12 字节头。
		b, err := buildDNS(f)
		if err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := wrapDNSForTransport(b, overTCP).SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		return buf.Bytes(), nil
	case *scenario.TFTPFields:
		// *scenario.TFTPTransferFields 不在此处理——宏在 flow 展开后已消失。
		b, err := serializeTFTP(f)
		if err != nil {
			return nil, fmt.Errorf("tftp: %w", err)
		}
		return b, nil
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
