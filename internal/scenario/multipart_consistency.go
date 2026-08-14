package scenario

import (
	"fmt"
	"strings"
)

// 本文件实现 MIME multipart 的一致性告警(非硬错),对齐 FTP 端口一致性告警风格
// (ftp_consistency.go):不强制联动,但配置不自洽时产告警,供用户复核。畸形用例可能故意
// 构造不一致,故只告警不阻断。
//
// 覆盖两类一致性:
//  1. boundary 一致性:父层 Content-Type 头的 boundary= 参数须与 multipart.Boundary(或默认值)
//     一致;父层有 multipart 但缺 Content-Type 头 → 告警。
//  2. CTE 一致性:part 设 encoding: base64 但 part 头 Content-Transfer-Encoding 缺失或与之
//     不符 → 告警。
//
// 第三类「boundary 串出现在 part body 内」(RFC 2046 §5.1.1:分界符须独占一行)需扫描**编码后**
// 实际落盘字节,放在 builder 序列化阶段(见 builder/multipart.go),scenario 层无编码逻辑。

// CheckMultipartConsistency 扫描所有带 multipart 的 http_request/http_response/eml_data 层,
// 校验 boundary / CTE 一致性,返回零到多条告警。
func CheckMultipartConsistency(s *Scenario) []string {
	if s == nil {
		return nil
	}
	var warnings []string
	for i, p := range s.Packets {
		for _, l := range p.Stack {
			warnings = append(warnings, checkLayerMultipartConsistency(fmt.Sprintf("packet[%d]", i), l)...)
		}
	}
	for i, f := range s.Flows {
		label := flowLabel(f.Name, i)
		for _, m := range f.Messages {
			for _, l := range m.Stack {
				warnings = append(warnings, checkLayerMultipartConsistency(label, l)...)
			}
		}
	}
	return warnings
}

// checkLayerMultipartConsistency 检查单个层的 multipart 一致性(若该层含 multipart)。
// label 是告警定位(flow 名或 packet 下标)。
func checkLayerMultipartConsistency(label string, l Layer) []string {
	var headers HeaderMap
	var multipart *MultipartBody
	switch f := l.Fields.(type) {
	case *HTTPReqFields:
		headers, multipart = f.Headers, f.Multipart
	case *HTTPRespFields:
		headers, multipart = f.Headers, f.Multipart
	case *EMLDataFields:
		headers, multipart = f.Headers, f.Multipart
	default:
		return nil
	}
	if multipart == nil {
		return nil
	}
	var warnings []string
	warnings = append(warnings, checkBoundaryConsistency(label, l.Type, headers, multipart)...)
	warnings = append(warnings, checkPartCTEConsistency(label, l.Type, multipart)...)
	return warnings
}

// checkBoundaryConsistency 校验父层 Content-Type 头的 boundary= 参数与 multipart 实际 boundary
// 是否一致;父层缺 Content-Type → 告警。
func checkBoundaryConsistency(label, layerType string, headers HeaderMap, m *MultipartBody) []string {
	actual := MultipartBoundary(m)
	ct, hasCT := headers.Get("Content-Type")
	if !hasCT {
		return []string{fmt.Sprintf(
			"%s 的 %s 层含 multipart 但缺 Content-Type 头(multipart 邮件/表单应声明 Content-Type: multipart/*; boundary=...)",
			label, layerType)}
	}
	declared := parseBoundaryParam(ct)
	if declared == "" {
		return []string{fmt.Sprintf(
			"%s 的 %s 层 Content-Type 头 %q 未带 boundary= 参数,但 multipart 实际使用 boundary %q",
			label, layerType, ct, actual)}
	}
	if !strings.EqualFold(declared, actual) {
		return []string{fmt.Sprintf(
			"%s 的 %s 层 Content-Type 头 boundary %q 与 multipart 实际 boundary %q 不一致",
			label, layerType, declared, actual)}
	}
	return nil
}

// checkPartCTEConsistency 校验每个 part 的 encoding 与其 Content-Transfer-Encoding 头是否一致。
// part 设 encoding(非 none)但缺 CTE 头、或 CTE 头与 encoding 不符 → 告警。
func checkPartCTEConsistency(label, layerType string, m *MultipartBody) []string {
	var warnings []string
	for i, p := range m.Parts {
		enc := p.Encoding
		if enc == "" || enc == "none" {
			continue
		}
		cte, hasCTE := p.Headers.Get("Content-Transfer-Encoding")
		if !hasCTE {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 multipart.parts[%d] 设 encoding %q 但缺 Content-Transfer-Encoding 头",
				label, layerType, i, enc))
			continue
		}
		if !strings.EqualFold(cte, enc) {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 multipart.parts[%d] encoding %q 与 Content-Transfer-Encoding 头 %q 不符",
				label, layerType, i, enc, cte))
		}
	}
	return warnings
}

// parseBoundaryParam 从 Content-Type 头值里解析 boundary= 参数的值(去引号)。
// 容忍参数间分号与空白;boundary 值可带双引号(RFC 2046 §5.1.1 允许 quoted-string)。
// 解析不到返回空串。对齐 ftp_consistency.go 的手写解析风格,不引第三方 MIME 库。
func parseBoundaryParam(ct string) string {
	// 逐段扫描 "key=value" 对(分号分隔),大小写不敏感匹配 boundary。
	for _, part := range splitParams(ct) {
		k, v, ok := splitKV(part)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "boundary") {
			v = strings.TrimSpace(v)
			// 去掉可选的双引号。
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			return v
		}
	}
	return ""
}

// splitParams 按 ';' 切分 Content-Type 值为参数段,跳过首段(media type 本身)。
// 不处理 quoted-string 内的分号(简化:合规 boundary 不含分号,RFC 2046 bchars 不含 ';')。
func splitParams(ct string) []string {
	parts := strings.Split(ct, ";")
	if len(parts) <= 1 {
		return nil
	}
	return parts[1:]
}

// splitKV 把 "key=value" 拆为 (key, value);无 '=' 返回 ok=false。
func splitKV(s string) (string, string, bool) {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return "", "", false
	}
	return k, v, true
}
