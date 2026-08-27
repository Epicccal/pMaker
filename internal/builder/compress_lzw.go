package builder

// compressLZW 把 b 编码为 UNIX compress(.Z) 格式字节流(RFC 9110 §8.4.1.1)。
// 标准库 compress/lzw 是 GIF/PDF 风味,不可复用,故此处自行实现。
//
// 确定性(CLAUDE.md 硬约束):maxbits=16 + block mode 钉死;码表用 map 做查表-插入,
// 但禁止任何 map 迭代——一次 range 就会让输出随机化、破坏 golden。error 恒为 nil,
// 保留返回值仅为与 compressCoding 各分支形态一致。
//
// .Z 格式:3 字节头 [0x1F 0x9D 0x90](maxbits=16 | 0x80 block mode),随后是 LSB-first
// 连续打包的 LZW 码流。起始码宽 9 bit,最大 16 bit;码 0-255 字面字节,257+ 复合码。
// 码之间无对齐填充,末尾不足一字节时零填充到字节边界。
//
// 码宽增长时机(ncompress 兼容,已对 gunzip 交叉验证):发码后 freeEnt++,当它越过
// maxcode+1(首个需要更宽码位的待分配码)时升档,比朴素的「freeEnt > maxcode」晚一拍,
// 与 gunzip 的 .Z 解码器严格对齐。码表满(freeEnt == 65536)后冻结:不再登记新项、不发
// 清除码,继续用已学字典编码后续输入。全程连续位打包、无组对齐填充(组补齐版本在码宽
// 跨越处会被 gunzip 误读)。
func compressLZW(in []byte) ([]byte, error) {
	const (
		magic1     = 0x1F
		magic2     = 0x9D
		maxbits    = 16
		blockMode  = 0x80
		initBits   = 9
		clearCode  = 256 // block-mode 清除码(本实现不发,见上)
		firstFree  = 257 // block mode 下首个空闲码
		maxmaxcode = 1 << maxbits
	)
	_ = clearCode // 保留:格式文档对齐用,本流不产生

	out := []byte{magic1, magic2, byte(maxbits) | blockMode} // 0x1F 0x9D 0x90
	if len(in) == 0 {
		return out, nil
	}

	nBits := initBits
	maxcode := (1 << nBits) - 1
	freeEnt := firstFree

	// 位缓冲:码 LSB-first 连续首尾相接;ensure 保证缓冲覆盖到目标 bit。
	var buf []byte
	bits := 0 // 已写入的总 bit 数
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

	table := make(map[uint32]uint16, maxmaxcode)

	ent := int(in[0])
	for i := 1; i < len(in); i++ {
		c := int(in[i])
		// fcode = (c << 16) | ent;c 占高 8 位、ent 占低 16 位,无重叠。
		fcode := uint32(c)<<16 | uint32(ent)
		if code, ok := table[fcode]; ok {
			ent = int(code)
			continue
		}
		put(ent)
		if freeEnt < maxmaxcode {
			table[fcode] = uint16(freeEnt)
			freeEnt++
			// 码宽增长:freeEnt 越过 maxcode+1 时升档(见函数注释的时机说明)。
			if freeEnt > maxcode+1 && nBits < maxbits {
				nBits++
				if nBits == maxbits {
					maxcode = maxmaxcode
				} else {
					maxcode = (1 << nBits) - 1
				}
			}
		}
		// 码表满(freeEnt == maxmaxcode):冻结,不再登记、不发清除码(见函数注释)。
		ent = c
	}
	put(ent)

	// 末尾 flush:ceil(bits/8) 字节;尾字节高位零填充,解码端据此精确命中 EOF。
	nbytes := (bits + 7) >> 3
	ensure(nbytes*8 - 1)
	out = append(out, buf[:nbytes]...)
	return out, nil
}
