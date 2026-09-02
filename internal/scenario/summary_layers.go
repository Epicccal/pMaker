package scenario

// 本文件持有「层名白名单」——哪些层在人类摘要里有应用层语义展示名。
// 这是 schema 元信息(不是终端排版),故留在 scenario 包:flow 包(非展示方)
// 也调用 SummaryLayerNames 填 scenario.Packet.SummaryLayers,不应让它依赖展示包。
// 终端排版(列宽对齐、方向箭头归一化等)已迁到 internal/summary。

// SummaryLayerNames 返回 stack 中适合在人类摘要里展示的协议层名。
func SummaryLayerNames(stack []Layer) []string {
	parts := make([]string, 0, len(stack))
	for _, l := range stack {
		name, ok := summaryLayerName(l.Type)
		if ok {
			parts = append(parts, name)
		}
	}
	return parts
}

func summaryLayerName(layerType string) (string, bool) {
	switch layerType {
	case "http_request", "http_response":
		return "http", true
	case "ftp_request", "ftp_response":
		return "ftp", true
	case "smtp_request", "smtp_response":
		return "smtp", true
	case "pop3_request", "pop3_response":
		return "pop3", true
	case "imap_request", "imap_response":
		return "imap", true
	case "eml_data":
		return "eml", true // 协议无关的 RFC 5322 邮件内容
	case "payload", "payload_hex", "tcp_session":
		return "", false
	default:
		return layerType, true
	}
}
