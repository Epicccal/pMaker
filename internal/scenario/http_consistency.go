package scenario

import (
	"fmt"
	"slices"
	"strings"
)

// 本文件实现 HTTP 的内容编码(CE)/传输编码(TE)成帧的一致性告警(非硬错),对齐
// multipart_consistency.go 风格:不强制联动,但配置不自洽时产告警,供用户复核。畸形用例
// (请求走私、evasion)可能故意构造不一致,故只告警不阻断。
//
// 覆盖:
//  1. TE 非空但 Transfer-Encoding 头缺失 / 头文本与列表不符 -> 疑似漏声明(或故意 evasion);
//  2. CE 非空但 Content-Encoding 头缺失 / 头文本与列表不符 -> 疑似漏声明(或故意 evasion);
//  3. Headers 有显式 Content-Length 且 TE 非空 -> RFC 9112 §6.1 CL+TE 冲突(走私特征);
//  4. TE 中 chunked 不在末位 -> 非常规顺序(RFC 9112:chunked 须末位);builder 仍按序 fold;
//  5. TE 含多个 chunked(双 chunked)-> 异常编码栈(IDS 绕过特征);放行。
//
// 大小写与归一:列表侧元素在 CodingList 解码时已归一为大写规范形;头侧(自由文本)比对时
// 按逗号切分、逐 token TrimSpace + ToUpper 后与列表大写形逐元素比。chunked 末位 / 多 chunked
// 判定同样在归一大写形(CHUNKED)上。
//
// auto_content_length 与特殊 HTTP 响应语义(仅 http_response):工具机械计算 CL,不理解
// HTTP 消息语义;1xx/204/304 会出 Warning 但照常出包(见 CheckHTTPRespConsistency)。
// CONNECT 同 HEAD:响应层无请求方法上下文,无法判定一个 2xx 是否为 CONNECT 响应,故不做处理。

// CheckHTTPConsistency 扫描所有 http_request/http_response 层的 CE/TE 一致性,返回零到多条告警。
func CheckHTTPConsistency(s *Scenario) []string {
	if s == nil {
		return nil
	}
	var warnings []string
	for i, p := range s.Packets {
		for _, l := range p.Stack {
			warnings = append(warnings, checkLayerHTTPConsistency(fmt.Sprintf("packet[%d]", i), l)...)
		}
	}
	for i, f := range s.Flows {
		label := flowLabel(f.Name, i)
		for _, m := range f.Messages {
			for _, l := range m.Stack {
				warnings = append(warnings, checkLayerHTTPConsistency(label, l)...)
			}
		}
	}
	return warnings
}

// checkLayerHTTPConsistency 检查单个 HTTP 层(若该层是 http_request/http_response)的
// CE/TE 一致性。label 是告警定位。
func checkLayerHTTPConsistency(label string, l Layer) []string {
	switch f := l.Fields.(type) {
	case *HTTPReqFields:
		return checkCodingsConsistency(label, l.Type, f.Headers, f.ContentEncoding, f.TransferEncoding)
	case *HTTPRespFields:
		w := checkCodingsConsistency(label, l.Type, f.Headers, f.ContentEncoding, f.TransferEncoding)
		return append(w, CheckHTTPRespConsistency(label, l.Type, f)...)
	default:
		return nil
	}
}

// checkCodingsConsistency 实现 http_request/http_response 共用的 CE/TE 一致性告警。
func checkCodingsConsistency(label, layerType string, headers HeaderMap, ce, te CodingList) []string {
	teEff := te.Effective()
	ceEff := ce.Effective()
	var warnings []string

	// 1. TE 与头一致性。
	if len(teEff) > 0 {
		warnings = append(warnings, checkCodingHeaderConsistency(label, layerType, "Transfer-Encoding", teEff, headers)...)
		// 3. CL + TE 冲突(走私特征)。auto_content_length=true + TE 非空已在校验硬错拦截,
		//    此处只判显式手写 CL 与 TE 并存(auto=false 走私路径)。
		if headers.Has("Content-Length") {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层同时含 Content-Length 头与 transfer_encoding(RFC 9112 §6.1:TE 存在时不得发 CL;CL+TE 并存是请求走私特征,如系故意请忽略)",
				label, layerType))
		}
		// 4. chunked 非末位。
		if idx := slices.Index(teEff, CodingChunked); idx >= 0 && idx != len(teEff)-1 {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 transfer_encoding 中 chunked 不在末位(RFC 9112:chunked 须末位;builder 仍按列表顺序 fold,适用于 evasion 测试)",
				label, layerType))
		}
		// 5. 多 chunked(双 chunked)。
		chunkedCount := 0
		for _, c := range teEff {
			if c == CodingChunked {
				chunkedCount++
			}
		}
		if chunkedCount >= 2 {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 transfer_encoding 含 %d 个 chunked(异常编码栈,IDS 绕过特征;builder 照常按序 fold 产出)",
				label, layerType, chunkedCount))
		}
	}

	// 2. CE 与头一致性。
	if len(ceEff) > 0 {
		warnings = append(warnings, checkCodingHeaderConsistency(label, layerType, "Content-Encoding", ceEff, headers)...)
	}

	return warnings
}

// checkCodingHeaderConsistency 校验 coding 列表与对应头文本是否一致(宽松包含)。
// headerName 是头名(如 "Transfer-Encoding");list 是归一后大写形列表。
// 头侧按逗号切分、逐 token TrimSpace + ToUpper 后与列表大写形逐元素比。
func checkCodingHeaderConsistency(label, layerType, headerName string, list CodingList, headers HeaderMap) []string {
	val, has := headers.Get(headerName)
	if !has {
		return []string{fmt.Sprintf(
			"%s 的 %s 层声明了 %s(%v)但缺 %s 头(头与外置编码不一致;如系故意 evasion 请忽略)",
			label, layerType, headerName, list, headerName)}
	}
	headerTokens := normalizeHeaderCodings(val)
	// 宽松包含:列表元素须在头 token 中出现,反之亦然(双向包含避免漏告警/误告警)。
	for _, c := range list {
		if !slices.Contains(headerTokens, c) {
			return []string{fmt.Sprintf(
				"%s 的 %s 层 %s 列表 %v 与 %s 头 %q 不符(头与外置编码不一致;如系故意 evasion 请忽略)",
				label, layerType, headerName, list, headerName, val)}
		}
	}
	for _, t := range headerTokens {
		if t == "" {
			continue
		}
		if !slices.Contains(list, t) {
			return []string{fmt.Sprintf(
				"%s 的 %s 层 %s 列表 %v 与 %s 头 %q 不符(头与外置编码不一致;如系故意 evasion 请忽略)",
				label, layerType, headerName, list, headerName, val)}
		}
	}
	return nil
}

// normalizeHeaderCodings 把头值按逗号切分、逐 token TrimSpace + ToUpper,返回大写规范形列表。
func normalizeHeaderCodings(val string) []string {
	var out []string
	for _, part := range strings.Split(val, ",") {
		t := strings.ToUpper(strings.TrimSpace(part))
		out = append(out, t)
	}
	return out
}

// CheckHTTPRespConsistency 是 http_response 侧 auto_content_length 语义告警的完整入口:
// 仅当 auto=true 且 status 落入特殊范围时触发。1xx/204 仅当 Body/Multipart 非空时触发;
// 304 无论 body 是否为空均触发。CONNECT 同 HEAD:响应层无请求方法上下文,不做处理。返回零到多条告警。
// 供 Warnings 汇流与测试直接调用。
func CheckHTTPRespConsistency(label, layerType string, f *HTTPRespFields) []string {
	if f == nil || !f.AutoContentLength {
		return nil
	}
	status := f.Status
	if status == 0 {
		status = 200
	}
	hasBody := f.Body != "" || f.Multipart != nil
	var warnings []string
	switch {
	case status >= 100 && status <= 199:
		if hasBody {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 status %d(1xx)带 body 且 auto_content_length=true(RFC 9110 §8.6:1xx 禁止 body 与 Content-Length;如系故意请设 auto_content_length: false 手写)",
				label, layerType, status))
		}
	case status == 204:
		if hasBody {
			warnings = append(warnings, fmt.Sprintf(
				"%s 的 %s 层 status 204(No Content)带 body 且 auto_content_length=true(RFC 9110:204 禁止 body 与 Content-Length;如系故意请设 auto_content_length: false 手写)",
				label, layerType))
		}
	case status == 304:
		warnings = append(warnings, fmt.Sprintf(
			"%s 的 %s 层 status 304(Not Modified)且 auto_content_length=true(304 的 CL 语义为对应 200 body 长度,非当前 wire body 长度;auto 只能按当前 body 字节填)",
			label, layerType))
	}
	return warnings
}
