package builder

import (
	"encoding/binary"
	"fmt"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// TFTP(RFC 1350 + RFC 2347 选项扩展)的手写字节编码:gopacket 无原生 TFTP layer。
// 所有 2 字节数字字段大端序;字符串 NUL 终止、原样透传(不做大小写规范化,保留畸形构造能力)。
//
// wire 格式:
//
//	RRQ/WRQ: | Opcode(2) | Filename(n) | 0x00 | Mode(n) | 0x00 | [Options…] |
//	DATA:    | 0x0003(2) | Block#(2) | Data(0–512) |
//	ACK:     | 0x0004(2) | Block#(2) |
//	ERROR:   | 0x0005(2) | ErrCode(2) | ErrMsg(n) | 0x00 |
//	OACK:    | 0x0006(2) | OptName(n) | 0x00 | OptVal(n) | 0x00 | … |
//
// 字段合法性由 scenario.Validate 在校验阶段拦截,本文件只做防御性兜底
// (block 解引用前判 nil),不重复互斥检查。

// serializeTFTP 按 opcode 分派编码路径;未知数字 opcode 只写 2 字节头(畸形通道)。
func serializeTFTP(f *scenario.TFTPFields) ([]byte, error) {
	op, err := scenario.ParseTFTPOpcode(f.Opcode)
	if err != nil {
		return nil, err
	}
	switch op {
	case 1, 2:
		return encodeTFTPRQ(f, op)
	case 3:
		return encodeTFTPData(f)
	case 4:
		return encodeTFTPACK(f)
	case 5:
		return encodeTFTPError(f)
	case 6:
		return encodeTFTPOACK(f)
	default:
		out := make([]byte, 2)
		binary.BigEndian.PutUint16(out, op)
		return out, nil
	}
}

// encodeTFTPRQ 编码 RRQ/WRQ:opcode + filename + mode(缺省 octet)+ 可选选项。
func encodeTFTPRQ(f *scenario.TFTPFields, op uint16) ([]byte, error) {
	mode := f.Mode
	if mode == "" {
		mode = "octet"
	}
	out := make([]byte, 0, 2+len(f.Filename)+1+len(mode)+1)
	out = appendOp(out, op)
	out = appendCString(out, f.Filename)
	out = appendCString(out, mode)
	for _, o := range f.Options {
		out = appendCString(out, o.Name)
		out = appendCString(out, o.Value)
	}
	return out, nil
}

// encodeTFTPData 编码 DATA:opcode + block# + 载荷(均空 = 0 字节末块)。
func encodeTFTPData(f *scenario.TFTPFields) ([]byte, error) {
	if f.Block == nil {
		return nil, fmt.Errorf("opcode data 需要 block(校验阶段应已拦截)")
	}
	var data []byte
	if f.DataHex != "" {
		b, err := scenario.ParsePayloadHex(f.DataHex)
		if err != nil {
			return nil, err
		}
		data = b
	} else {
		data = []byte(f.Data)
	}
	out := make([]byte, 0, 4+len(data))
	out = appendOp(out, 3)
	out = binary.BigEndian.AppendUint16(out, *f.Block)
	return append(out, data...), nil
}

// encodeTFTPACK 编码 ACK:opcode + block#。
func encodeTFTPACK(f *scenario.TFTPFields) ([]byte, error) {
	if f.Block == nil {
		return nil, fmt.Errorf("opcode ack 需要 block(校验阶段应已拦截)")
	}
	out := make([]byte, 0, 4)
	out = appendOp(out, 4)
	return binary.BigEndian.AppendUint16(out, *f.Block), nil
}

// encodeTFTPError 编码 ERROR:opcode + code(缺省 0)+ NUL 终止的 message(可空)。
func encodeTFTPError(f *scenario.TFTPFields) ([]byte, error) {
	code, err := scenario.ParseTFTPErrorCode(f.Code)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(f.Message)+1)
	out = appendOp(out, 5)
	out = binary.BigEndian.AppendUint16(out, code)
	return appendCString(out, f.Message), nil
}

// encodeTFTPOACK 编码 OACK:opcode + 选项键值对序列。
// 空选项列表在校验阶段已拦截,此处返回空 OACK 兜底(2 字节头)。
func encodeTFTPOACK(f *scenario.TFTPFields) ([]byte, error) {
	out := make([]byte, 0, 2)
	out = appendOp(out, 6)
	for _, o := range f.Options {
		out = appendCString(out, o.Name)
		out = appendCString(out, o.Value)
	}
	return out, nil
}

// appendOp 追加 2 字节大端 opcode。
func appendOp(out []byte, op uint16) []byte {
	return binary.BigEndian.AppendUint16(out, op)
}

// appendCString 追加 NUL 终止字符串(原样透传)。
func appendCString(out []byte, s string) []byte {
	out = append(out, s...)
	return append(out, 0x00)
}
