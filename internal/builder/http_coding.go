package builder

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/util/compress"
)

// 本文件实现 HTTP 的内容编码(CE)/传输编码(TE)成帧与自动 Content-Length,
// 由 serializeHTTPReq/Resp 在 body 生产之后按固定顺序叠用。
//
// 固定作用顺序:
//
//	raw     := httpBody(body, multipart)                     // 1 body 生产(字面 / multipart 统一出口)
//	repr    := applyContentCodings(raw, f.ContentEncoding)   // 2 表示层编码(CE 列表按序 fold)
//	clBasis := len(repr)                                     // CL 基准 = CE 之后、TE 之前
//	bodyOut := applyTransferCodings(repr, f.TransferEncoding, opts) // 3 传输层编码/成帧(TE 列表按序 fold)
//	hdrs    := applyAutoContentLength(f.Headers, f.AutoContentLength, clBasis) // 4 自动 CL(TE 非空时互斥,走不到)
//
// 设计立场:外置参数只表达「我要工具做这件事」,头里的值是用户自由文本——成帧不解析头、
// 头不驱动成帧。合规 chunked/gzip 成为一等公民;走私(CL.TE/TE.CL)、evasion 等畸形靠
// 「关掉外置开关 + 头里自由手写」自然构造。

// compressLevel 是固定压缩级别,保证同输入 → 逐字节相同输出(CLAUDE.md 确定性硬约束)。
// 选 BestSpeed(1)而非 Default(-1):Default 在不同 Go 版本/实现间理论可能漂移,
// 显式钉死级别消除不确定性,且 BestSpeed 输出更小可读、测试 golden 稳定。
const compressLevel = flate.BestSpeed

// applyContentCodings 按 CE 列表顺序对 body 逐个 fold(表示层编码)。
// 空列表 / IsNone -> 原样返回。穷尽 switch 仅允许 GZIP/DEFLATE/DEFLATE_RAW/BR/COMPRESS;
// 落 default(如 CHUNKED)返回错误——CHUNKED 是传输编码,CE 含 chunked 已在 scenario
// 校验阶段拦截,此处是 builder 层防线。fold 顺序 = 列表顺序:
// content_encoding: [deflate, gzip] 构造 gzip(deflate(body))。
func applyContentCodings(b []byte, list scenario.CodingList) ([]byte, error) {
	effective := list.Effective()
	if len(effective) == 0 {
		return b, nil
	}
	var err error
	for _, name := range effective {
		b, err = compressCoding(b, name)
		if err != nil {
			return nil, fmt.Errorf("content_encoding %q: %w", name, err)
		}
	}
	return b, nil
}

// applyTransferCodings 按 TE 列表顺序对 body 逐个 fold(传输层编码/成帧)。
// 空列表 / IsNone -> 原样返回。穷尽 switch 允许 GZIP/DEFLATE/DEFLATE_RAW/COMPRESS/CHUNKED;
// CHUNKED -> chunkedFrame(b, opts.Size);其余 -> compressCoding。
// fold 顺序 = 列表顺序,天然支持链式([gzip, chunked] = 先 gzip 后 chunked 成帧)与
// 异常栈([chunked, gzip]、双 chunked——builder 机械按序 fold,合规性由校验/告警判,
// 构造能力不设限)。签名携带 ChunkedOptions 避免函数体隐式捕获字段。
func applyTransferCodings(b []byte, list scenario.CodingList, opts scenario.ChunkedOptions) ([]byte, error) {
	effective := list.Effective()
	if len(effective) == 0 {
		return b, nil
	}
	var err error
	for _, name := range effective {
		switch name {
		case scenario.CodingChunked:
			b = chunkedFrame(b, opts.Size)
		case scenario.CodingGzip, scenario.CodingDeflate, scenario.CodingDeflateRaw, scenario.CodingCompress:
			b, err = compressCoding(b, name)
			if err != nil {
				return nil, fmt.Errorf("transfer_encoding %q: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("transfer_encoding %q 非法(合法:chunked/gzip/deflate/deflate_raw/compress)", name)
		}
	}
	return b, nil
}

// compressCoding 对 body 做单次压缩编码,返回确定性字节。
//   - gzip:compress/gzip(RFC 1952),MTIME 置零、OS 字节稳定;
//   - deflate:compress/zlib(RFC 1950,zlib wrapper);
//   - deflate_raw:compress/flate(RFC 1951,raw deflate 无 wrapper);
//   - compress:自实现 UNIX compress(.Z) LZW(RFC 9110 §8.4.1.1,见 compress_lzw.go)。
//
// 确定性:用 NewWriterLevel 钉固定压缩级别;gzip 头 MTIME 须为零值、OS 字节稳定;
// compress 钉死 maxbits=16 + block mode、码表冻结不发清除码。实现时实测两次输出逐字节
// 相同再定 golden(CLAUDE.md 确定性硬约束)。
func compressCoding(b []byte, name string) ([]byte, error) {
	switch name {
	case scenario.CodingGzip:
		var buf bytes.Buffer
		w, err := gzip.NewWriterLevel(&buf, compressLevel)
		if err != nil {
			return nil, fmt.Errorf("gzip NewWriterLevel: %w", err)
		}
		// MTIME 显式置零(零值已是 0,这里写明意图,避免未来误改)。
		w.ModTime = time.Time{}
		// OS 字节:gzip.NewWriterLevel 默认 OS=255(unknown),跨平台稳定,不改。
		if _, err := w.Write(b); err != nil {
			return nil, fmt.Errorf("gzip write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("gzip close: %w", err)
		}
		return buf.Bytes(), nil
	case scenario.CodingDeflate:
		var buf bytes.Buffer
		w, err := zlib.NewWriterLevel(&buf, compressLevel)
		if err != nil {
			return nil, fmt.Errorf("deflate NewWriterLevel: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return nil, fmt.Errorf("deflate write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("deflate close: %w", err)
		}
		return buf.Bytes(), nil
	case scenario.CodingDeflateRaw:
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, compressLevel)
		if err != nil {
			return nil, fmt.Errorf("deflate_raw NewWriter: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return nil, fmt.Errorf("deflate_raw write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("deflate_raw close: %w", err)
		}
		return buf.Bytes(), nil
	case scenario.CodingBr:
		var buf bytes.Buffer
		// quality 固定 brotli.BestSpeed(0),与 gzip 侧 compressLevel=flate.BestSpeed 同理:
		// 钉死级别消除不同版本/平台漂移,保证同输入→逐字节相同输出(golden 可比对)。
		w := brotli.NewWriterLevel(&buf, brotli.BestSpeed)
		if _, err := w.Write(b); err != nil {
			return nil, fmt.Errorf("br write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("br close: %w", err)
		}
		return buf.Bytes(), nil
	case scenario.CodingCompress:
		return compress.EncodeLZW(b)
	default:
		return nil, fmt.Errorf("不支持的压缩编码 %q(合法:gzip/deflate/deflate_raw/br/compress)", name)
	}
}

// chunkedFrame 把 body 按 size 切块做 HTTP chunked transfer-encoding 成帧(RFC 9112 §7.1)。
//   - size==0:整个 body 作为一个 chunk(契约行为);
//   - size>0:按 size 切分,每块长自动十六进制;
//   - 始终追加合法终止块 "0\r\n\r\n"。
//
// size<0 在 scenario 校验阶段已是硬错(http_validate.go),不应到达 builder;此处 size<=0 分支
// 把负数一并归入「整段一块」仅作 defense-in-depth 兜底,非契约行为,不应被测试当作等价语义固化。
//
// 块格式:"%x\r\n" + data + "\r\n"(块长十六进制)。空 body 合规输出 "0\r\n\r\n"(仅终止块)。
func chunkedFrame(b []byte, size int) []byte {
	var out bytes.Buffer
	if size <= 0 {
		// 整段一块。空 body 不写数据块(只留终止块,合规输出 "0\r\n\r\n")。
		// 一般情况下，size 不会小于0。
		if len(b) > 0 {
			writeChunk(&out, b)
		}
	} else {
		for i := 0; i < len(b); i += size {
			end := min(i+size, len(b))
			writeChunk(&out, b[i:end])
		}
	}
	// 终止块。
	out.WriteString("0\r\n\r\n")
	return out.Bytes()
}

// writeChunk 写一个 chunk:"%x\r\n" + data + "\r\n"。
func writeChunk(out *bytes.Buffer, data []byte) {
	out.WriteString(strconv.FormatInt(int64(len(data)), 16))
	out.WriteString("\r\n")
	out.Write(data)
	out.WriteString("\r\n")
}

// applyAutoContentLength 按开关回填/覆盖 Content-Length 头值。
//   - on==false:原样返回(不动 Header);
//   - on==true:拷贝 h(不 mutate 原值,保确定性/可重复构建),存在 Content-Length(大小写
//     不敏感)则原地覆盖值、位置不变,不存在则末尾追加 "Content-Length: n"。
//
// 显式 CL 覆盖是核心用途之一:用户在 headers 手写 Content-Length: 999 再开启
// auto_content_length: true,工具以计算值覆盖该位置的值——精确设计意图,非副作用。
// 如需保留手写值(构造故意错误的 CL),应设 auto_content_length: false。
func applyAutoContentLength(h scenario.HeaderMap, on bool, n int) scenario.HeaderMap {
	if !on {
		return h
	}
	out := make(scenario.HeaderMap, len(h))
	copy(out, h)
	value := strconv.Itoa(n)
	replaced := false
	for i := range out {
		if strings.EqualFold(out[i].Key, "Content-Length") {
			out[i].Value = value
			replaced = true
			break // 多 CL 已由校验拦截;此处只覆盖首个
		}
	}
	if !replaced {
		out = append(out, scenario.HeaderEntry{Key: "Content-Length", Value: value})
	}
	return out
}
