package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
)

// 本文件是 compress_lzw.go 的单元测试(一一对应规约:compress_lzw.go ↔ compress_lzw_test.go)。
//
// 覆盖点:
//   - round-trip:test-only LZW 解码器(连续位打包、码宽在 freeEnt>maxcode+1 时升档)解压
//     compressLZW 输出还原原文;
//   - 确定性:同输入两次调用逐字节相同;
//   - 边界:空 body(只出 3 字节头)、单字节、跨 9→10 位码宽增长;
//   - 码表满路径:造确定能填满 65536 项码表的输入,断言输出流不含清除码 256(本实现冻结码表、
//     不发清除)且 round-trip 正确。

// decodeLZW 是 test-only UNIX compress(.Z)LZW 解码器,用于 round-trip 验证 compressLZW。
// 标准库 compress/lzw 是 GIF/PDF 风味(无 .Z 头、码宽上限 12),不可复用,故此处自带。
// 与 compressLZW 对称:连续 LSB-first 位打包(无组对齐填充),码宽在 freeEnt > maxcode+1
// 时升档。末尾尾字节高位零填充,读完即止。
func decodeLZW(t *testing.T, in []byte) []byte {
	t.Helper()
	if len(in) < 3 || in[0] != 0x1F || in[1] != 0x9D {
		t.Fatalf("decodeLZW: 坏 .Z 头 % x", in[:min(3, len(in))])
	}
	maxbits := int(in[2]) & 0x1F
	blockMode := in[2]&0x80 != 0
	if maxbits > 16 || maxbits < 9 {
		t.Fatalf("decodeLZW: 非法 maxbits %d", maxbits)
	}
	data := in[3:]
	if len(data) == 0 {
		return nil
	}

	nBits := 9
	maxcode := (1 << nBits) - 1
	clearCode := 256
	firstFree := 257
	freeEnt := firstFree
	if !blockMode {
		clearCode = -1
		firstFree = 256
		freeEnt = firstFree
	}

	prefix := make([]int, 1<<maxbits)
	suffix := make([]uint8, 1<<maxbits)
	for i := range 256 {
		prefix[i] = 0
		suffix[i] = uint8(i)
	}

	var out bytes.Buffer
	bitPos := 0 // data 内的绝对 bit 偏移
	totalBits := len(data) * 8

	// nextCode 连续读一个 LSB-first 码;ok=false 表示已到流末尾。
	nextCode := func() (int, bool) {
		if bitPos+nBits > totalBits {
			return 0, false
		}
		code := 0
		for i := 0; i < nBits; i++ {
			p := bitPos >> 3
			if (data[p]>>uint(bitPos&7))&1 != 0 {
				code |= 1 << i
			}
			bitPos++
		}
		return code, true
	}

	// decodeString 沿 prefix/suffix 链回溯,返回 code 对应的字符串(正序)。
	// 码 0-255 为单字节字面量;码 257+ 为复合码。
	decodeString := func(code int) []byte {
		var stack []byte
		cur := code
		for cur >= 256 {
			stack = append(stack, suffix[cur])
			cur = prefix[cur]
		}
		stack = append(stack, uint8(cur))
		// 反转。
		for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
			stack[i], stack[j] = stack[j], stack[i]
		}
		return stack
	}

	// addEntry 登记新表项 prefix=old、suffix=首字节;维护码宽升档。
	//
	// 升档时机与编码器故意差一档:标准 LZW 解码器的 freeEnt 比编码器恒滞后一项
	// (解码器每读一个码才登记上一码对应的表项,故 freeEnt 总比编码器少 1)。编码器在
	// freeEnt > maxcode+1 时升档;解码器若用同一阈值,升档会晚一个码 —— 导致编码器
	// 用新宽度发的那个码被解码器按旧宽度读,位流错位。故解码器用 freeEnt > maxcode
	// (早一档)补偿滞后,使两者在同一码边界升档。
	addEntry := func(old, firstByte int) {
		if freeEnt >= (1 << maxbits) {
			return // 码表冻结
		}
		prefix[freeEnt] = old
		suffix[freeEnt] = uint8(firstByte)
		freeEnt++
		if freeEnt > maxcode && nBits < maxbits {
			nBits++
			if nBits == maxbits {
				maxcode = 1 << maxbits
			} else {
				maxcode = (1 << nBits) - 1
			}
		}
	}

	old := -1
	for {
		code, ok := nextCode()
		if !ok {
			break
		}
		if blockMode && code == clearCode {
			// 本实现的流不产生清除码;若遇到,按 .Z 语义重置(防御性)。
			nBits = 9
			maxcode = (1 << nBits) - 1
			freeEnt = firstFree
			old = -1
			continue
		}

		var entry []byte
		if code < freeEnt {
			entry = decodeString(code)
		} else if code == freeEnt && old != -1 {
			// KwKwK:码等于「下一个待分配码」,串 = string(old) + 首字节(string(old))。
			s := decodeString(old)
			entry = s
			entry = append(entry, s[0])
		} else {
			t.Fatalf("decodeLZW: 坏码 %d >= freeEnt %d (输入非合法 .Z 流)", code, freeEnt)
		}
		out.Write(entry)

		if old != -1 {
			addEntry(old, int(entry[0]))
		}
		old = code
	}
	return out.Bytes()
}

func TestCompressLZW_RoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x41},
		[]byte("A"),
		[]byte("Hello, World!"),
		[]byte("The quick brown fox jumps over the lazy dog. 1234567890"),
		bytes.Repeat([]byte("ABCDEFGH"), 64), // 跨 9→10 位码宽增长
		bytes.Repeat([]byte("ab"), 1000),     // 中等重复,触发多次码宽增长
		bytes.Repeat([]byte("ab"), 50000),    // 跨多次码宽增长
		bytes.Repeat([]byte("abc"), 7000),    // 21000 字节,跨码宽增长
		[]byte("<html><body>Hello from pMaker compress content encoding example</body></html>\n"),
	}
	for _, body := range cases {
		enc, err := builder.CompressLZWForTest(body)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		// 头校验。
		if len(enc) < 3 || enc[0] != 0x1F || enc[1] != 0x9D {
			t.Errorf("坏 .Z 头: % x", enc[:min(3, len(enc))])
			continue
		}
		if enc[2] != 0x90 {
			t.Errorf("flags=%#x, want 0x90 (maxbits=16|blockmode)", enc[2])
		}
		if len(body) == 0 {
			if len(enc) != 3 {
				t.Errorf("空 body 应只出 3 字节头, got len=%d", len(enc))
			}
			continue
		}
		dec := decodeLZW(t, enc)
		if !bytes.Equal(dec, body) {
			t.Errorf("round-trip 不符(len=%d):\n got %q\n want %q", len(body), dec, body)
		}
	}
}

func TestCompressLZW_Deterministic(t *testing.T) {
	body := []byte("Hello from pMaker! The quick brown fox jumps over the lazy dog. 1234567890")
	c1, _ := builder.CompressLZWForTest(body)
	c2, _ := builder.CompressLZWForTest(body)
	if !bytes.Equal(c1, c2) {
		t.Errorf("两次压缩结果不一致(确定性失败): len=%d vs %d", len(c1), len(c2))
	}
}

// TestCompressLZW_TableFull 断言码表满路径:造确定能填满 65536 项码表的高熵输入,
// 本实现采用「冻结码表、不发清除码」策略(ncompress block-mode 语义),故输出流中
// **不应出现清除码 256**;且 round-trip 仍正确(冻结后继续用已学字典解码)。这是整个
// 实现最易错的一段,直接断言而非用「压缩率」间接推断。
func TestCompressLZW_TableFull(t *testing.T) {
	// 高熵(无重复)输入迫使码表快速填满:每个新二字节对都会占用一个码表项。
	body := make([]byte, 0, 1<<18)
	for i := range 1 << 18 {
		body = append(body, byte(i*73%251))
	}
	enc, _ := builder.CompressLZWForTest(body)
	if containsClearCode(enc) {
		t.Errorf("本实现冻结码表、不应发清除码 256,但输出流中检测到清除码")
	}
	dec := decodeLZW(t, enc)
	if !bytes.Equal(dec, body) {
		t.Errorf("码表满后 round-trip 不符: got len=%d, want len=%d", len(dec), len(body))
	}
}

// containsClearCode 扫描 .Z 流,检测是否出现清除码 256。镜像 decodeLZW 的解码语义:
// 连续位打包、首码不登记表项、之后每码登记一项、码宽在 freeEnt > maxcode 时升档
// (解码侧阈值,补偿编/解码 freeEnt 滞后一项)。
func containsClearCode(in []byte) bool {
	if len(in) < 3 {
		return false
	}
	data := in[3:]
	nBits := 9
	maxcode := (1 << nBits) - 1
	freeEnt := 257
	clearCode := 256
	bitPos := 0
	totalBits := len(data) * 8
	old := -1
	for bitPos+nBits <= totalBits {
		code := 0
		for i := 0; i < nBits; i++ {
			p := bitPos >> 3
			if (data[p]>>uint(bitPos&7))&1 != 0 {
				code |= 1 << i
			}
			bitPos++
		}
		if code == clearCode {
			return true
		}
		// 登记表项:首码(old==-1)不登记,与解码器一致。
		if old != -1 && freeEnt < (1<<16) {
			freeEnt++
			if freeEnt > maxcode && nBits < 16 {
				nBits++
				if nBits == 16 {
					maxcode = 1 << 16
				} else {
					maxcode = (1 << nBits) - 1
				}
			}
		}
		old = code
	}
	return false
}
