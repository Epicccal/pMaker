package builder

import (
	"fmt"

	"github.com/gopacket/gopacket"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// PayloadBytes 返回一个 payload 生产层序列化后的字节。
// 供 flow 展开器取长度并按 MSS 切段(与 serializeStack 复用同一套序列化)。
func PayloadBytes(l scenario.Layer) ([]byte, error) {
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
		// DNS 是最内层,单层 SerializeTo 即产出完整 DNS 消息字节,形态与 wire 上
		// UDP payload 一致(buildDNS 可能返回 gopacket layers.DNS 或手写 dnsRawLayer,
		// 两者都实现 SerializeTo)。FixLengths 必开:段计数与 RDLENGTH 由它补齐,
		// 关掉会产出全零计数的 12 字节头。供 UDP flow 的 message.stack 产 DNS 问答;
		// TCP flow 的拦截在校验层(DNS-over-TCP 需 2 字节长度前缀,见 dns.md)。
		b, err := buildDNS(f)
		if err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := b.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
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
