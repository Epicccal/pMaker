package builder

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// serializeHTTPReq/Resp:把结构化 HTTP 序列化为 TCP payload 字节。
// 头按 YAML 声明顺序输出(保留原序、支持重复头如多个 Set-Cookie)。
// body 经「生产(字面/multipart)-> content_encoding -> transfer_encoding 成帧」三步,
// auto_content_length 算的是 content_encoding 之后、成帧之前的长度;true 时回填/覆盖
// Content-Length 头值(缺则末尾追加)、false 时不动 Header。成帧不解析头、头不驱动成帧
// (走私/evasion 靠头自由文本 + 外置参数关闭构造)。详见 http_coding.go。
func serializeHTTPReq(f *scenario.HTTPReqFields) ([]byte, error) {
	method := orDefault(f.Method, "GET")
	url := orDefault(f.URL, "/")
	ver := orDefault(f.Version, "HTTP/1.1")

	bodyOut, hdrs, err := httpPayload(f.Body, f.Multipart, f.ContentEncoding, f.TransferEncoding, f.Chunked, f.Headers, f.AutoContentLength)
	if err != nil {
		return nil, fmt.Errorf("http_request 序列化: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, url, ver)
	writeHeaders(&b, hdrs)
	b.WriteString("\r\n")
	b.Write(bodyOut)
	return []byte(b.String()), nil
}

func serializeHTTPResp(f *scenario.HTTPRespFields) ([]byte, error) {
	ver := orDefault(f.Version, "HTTP/1.1")
	status := f.Status
	if status == 0 {
		status = 200
	}
	reason := orDefault(f.Reason, http.StatusText(status))

	bodyOut, hdrs, err := httpPayload(f.Body, f.Multipart, f.ContentEncoding, f.TransferEncoding, f.Chunked, f.Headers, f.AutoContentLength)
	if err != nil {
		return nil, fmt.Errorf("http_response 序列化: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", ver, status, reason)
	writeHeaders(&b, hdrs)
	b.WriteString("\r\n")
	b.Write(bodyOut)
	return []byte(b.String()), nil
}

// httpPayload 是 http_request/http_response 共用的 body/headers 产出管线(两侧对称)。
// 固定作用顺序:body 生产 -> CE -> CL 基准 -> TE 成帧 -> 自动 CL 回填。
// 返回成帧后的 body 字节与(可能被自动 CL 覆盖的)headers。
func httpPayload(body string, m *scenario.MultipartBody, ce, te scenario.CodingList, chunked *scenario.ChunkedOptions, headers scenario.HeaderMap, autoCL bool) ([]byte, scenario.HeaderMap, error) {
	raw, err := httpBody(body, m)
	if err != nil {
		return nil, nil, fmt.Errorf("body 生产: %w", err)
	}
	repr, err := applyContentCodings(raw, ce)
	if err != nil {
		return nil, nil, fmt.Errorf("内容编码: %w", err)
	}
	clBasis := len(repr)
	bodyOut, err := applyTransferCodings(repr, te, chunkedOpts(chunked))
	if err != nil {
		return nil, nil, fmt.Errorf("传输编码: %w", err)
	}
	// AutoContentLength 取的是 Content-Encoding 后的载荷长度（clBasis）
	// Content-Length 与 Transfer-Encoding 互斥，即使 Transfer-Encoding 中
	// 不包含 Chunked，也不会携带 Content-Length。
	hdrs := applyAutoContentLength(headers, autoCL, clBasis)
	return bodyOut, hdrs, nil
}

// chunkedOpts 把可空 *ChunkedOptions 归一为零值 ChunkedOptions(nil 与 size=0 行为相同)。
func chunkedOpts(c *scenario.ChunkedOptions) scenario.ChunkedOptions {
	if c == nil {
		return scenario.ChunkedOptions{}
	}
	return *c
}

// httpBody 取 HTTP 的 body 字节:设了 multipart 则序列化 multipart(取代字面 body),
// 否则用字面 body。校验已保证二者互斥。
func httpBody(body string, m *scenario.MultipartBody) ([]byte, error) {
	if m != nil {
		return serializeMultipart(m)
	}
	return []byte(body), nil
}

// writeHeaders 按 HeaderMap 原序逐条原样输出头。Content-Length 不在此处理——自动 CL
// 由 applyAutoContentLength 预处理后交给本函数。
func writeHeaders(b *strings.Builder, h scenario.HeaderMap) {
	h.Range(func(k, v string) {
		fmt.Fprintf(b, "%s: %s\r\n", k, v)
	})
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
