// Package compress 提供 pMaker 用到的传输/内容编码原语。
//
// 当前实现:UNIX compress(.Z)LZW 编解码(RFC 9110 §8.4.1.1)。
// 标准库 compress/lzw 是 GIF/PDF 风味(无 .Z 头、码宽上限 12),不可复用,故自行实现。
package compress

import "fmt"

// .Z 格式常量。
const (
	magic1        = byte(0x1F)
	magic2        = byte(0x9D)
	flagMaxbits   = byte(0x1F) // 低 5 位
	flagBlockMode = byte(0x80) // bit7
	flagReserved  = byte(0x60) // bit5/bit6,保留位

	lzwInitBits   = 9
	lzwMaxbits    = 16
	lzwMaxmaxcode = 1 << lzwMaxbits

	// block mode 下 256 是清除码,首个空闲码为 257。
	lzwClearCode = 256
	lzwFirstFree = 257
)

// EncodeLZW 把 b 编码为 UNIX compress(.Z)格式字节流。
//
// 确定性(CLAUDE.md 硬约束):maxbits=16 + block mode 钉死;全程不用 time.Now()。
// 码表用 map 做查表-插入,但禁止任何 map 迭代——一次 range 就会让输出随机化。
//
// .Z 格式:3 字节头 [0x1F 0x9D 0x90](maxbits=16 | 0x80 block mode),随后是 LSB-first
// 连续打包的 LZW 码流。起始码宽 9 bit,最大 16 bit;码 0-255 字面字节,257+ 复合码。
// 码之间无对齐填充,末尾不足一字节时零填充到字节边界。
//
// 码宽增长时机(ncompress 兼容):发码后 freeEnt++,当它越过 maxcode+1 时升档,
// 比朴素的「freeEnt > maxcode」晚一拍,与 gunzip 的 .Z 解码器严格对齐。
// 码表满(freeEnt == 65536)后冻结:不再登记新项、不发清除码,继续用已学字典编码。
// error 恒为 nil,保留返回值仅为与调用侧各分支形态一致。
func EncodeLZW(in []byte) ([]byte, error) {
	out := []byte{magic1, magic2, byte(lzwMaxbits) | flagBlockMode} // 0x1F 0x9D 0x90
	if len(in) == 0 {
		return out, nil
	}

	nBits := lzwInitBits
	maxcode := (1 << nBits) - 1
	freeEnt := lzwFirstFree

	// 位缓冲:码 LSB-first 连续首尾相接。
	var buf []byte
	bits := 0
	ensure := func(bitIdx int) {
		need := (bitIdx >> 3) + 1
		for len(buf) < need {
			buf = append(buf, 0)
		}
	}
	put := func(code int) {
		startBit := bits
		for i := 0; i < nBits; i++ {
			if (code>>i)&1 != 0 {
				bp := startBit + i
				ensure(bp)
				buf[bp>>3] |= 1 << uint(bp&7)
			}
		}
		bits += nBits
	}

	table := make(map[uint32]uint16, lzwMaxmaxcode)

	ent := int(in[0])
	for i := 1; i < len(in); i++ {
		c := int(in[i])
		fcode := uint32(c)<<16 | uint32(ent)
		if code, ok := table[fcode]; ok {
			ent = int(code)
			continue
		}
		put(ent)
		if freeEnt < lzwMaxmaxcode {
			table[fcode] = uint16(freeEnt)
			freeEnt++
			if freeEnt > maxcode+1 && nBits < lzwMaxbits {
				nBits++
				if nBits == lzwMaxbits {
					maxcode = lzwMaxmaxcode
				} else {
					maxcode = (1 << nBits) - 1
				}
			}
		}
		ent = c
	}
	put(ent)

	nbytes := (bits + 7) >> 3
	ensure(nbytes*8 - 1)
	out = append(out, buf[:nbytes]...)
	return out, nil
}

// DecodeLZW 解码一段完整的 .Z 字节流,返回原文。
// 头部非法、标志位不支持、或码流损坏时返回 error。
//
// 升档时机与编码器差一档:解码器 freeEnt 恒比编码器滞后一项(每读一个码才登记上一码
// 的表项),故解码器用 freeEnt > maxcode(早一档)补偿滞后,使两者在同一码边界升档。
func DecodeLZW(in []byte) ([]byte, error) {
	if len(in) < 3 || in[0] != magic1 || in[1] != magic2 {
		return nil, fmt.Errorf("compress: 坏 .Z 头 % x", in[:min(3, len(in))])
	}

	flags := in[2]
	maxbits := int(flags & flagMaxbits)
	blockMode := flags&flagBlockMode != 0
	if maxbits < 9 || maxbits > 16 {
		return nil, fmt.Errorf("compress: 不支持的 maxbits %d(flags=%#x),仅支持 9-16", maxbits, flags)
	}
	if flags&flagReserved != 0 {
		return nil, fmt.Errorf("compress: flags=%#x 置了保留位 %#x,本解码器不支持", flags, flags&flagReserved)
	}

	data := in[3:]
	if len(data) == 0 {
		return nil, nil
	}

	nBits := 9
	maxcode := (1 << nBits) - 1
	clearCode := lzwClearCode
	firstFree := lzwFirstFree
	if !blockMode {
		clearCode = -1
		firstFree = 256
	}
	freeEnt := firstFree

	prefix := make([]int, 1<<maxbits)
	suffix := make([]uint8, 1<<maxbits)
	for i := range 256 {
		suffix[i] = uint8(i)
	}

	out := make([]byte, 0, len(data))
	bitPos := 0
	totalBits := len(data) * 8

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

	decodeString := func(code int) []byte {
		var stack []byte
		cur := code
		for cur >= 256 {
			stack = append(stack, suffix[cur])
			cur = prefix[cur]
		}
		stack = append(stack, uint8(cur))
		for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
			stack[i], stack[j] = stack[j], stack[i]
		}
		return stack
	}

	addEntry := func(old, firstByte int) {
		if freeEnt >= (1 << maxbits) {
			return
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
			nBits = 9
			maxcode = (1 << nBits) - 1
			freeEnt = firstFree
			old = -1
			continue
		}

		var entry []byte
		switch {
		case code < freeEnt:
			entry = decodeString(code)
		case code == freeEnt && old != -1:
			s := decodeString(old)
			entry = s
			entry = append(entry, s[0])
		default:
			return nil, fmt.Errorf("compress: 坏码 %d >= freeEnt %d(输入非合法 .Z 流)", code, freeEnt)
		}
		out = append(out, entry...)

		if old != -1 {
			addEntry(old, int(entry[0]))
		}
		old = code
	}
	return out, nil
}
