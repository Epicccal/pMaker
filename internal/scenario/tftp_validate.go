package scenario

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// 本文件承载 tftp 层与 tftp_transfer 宏的硬错校验:
// opcode / error code 的「字符串名或数字」解析、按 opcode 的字段约束、宏字段校验。
// 解析函数导出供 builder 复用,保证校验与编码认识同一张名字表。

// tftpOpcodeNames 是 RFC 1350 的 opcode 字符串名表(RFC 2347 补 oack=6);数字 opcode 直接透传。
var tftpOpcodeNames = map[string]uint16{
	"rrq":   1,
	"wrq":   2,
	"data":  3,
	"ack":   4,
	"error": 5,
	"oack":  6,
}

// tftpErrorCodes 是 RFC 1350 的错误码字符串名表(RFC 2347 补 option_negotiation=8);数字 code 直接透传。
var tftpErrorCodes = map[string]uint16{
	"not_defined":        0,
	"file_not_found":     1,
	"access_violation":   2,
	"disk_full":          3,
	"illegal_operation":  4,
	"unknown_tid":        5,
	"file_exists":        6,
	"no_such_user":       7,
	"option_negotiation": 8,
}

// ParseTFTPOpcode 解析 opcode 字段:字符串名(大小写不敏感)或数字(≤0xffff)。
// 未写(Kind==0)或显式空串均为硬错 —— opcode 是 tftp 层唯一必填字段,分派全靠它。
func ParseTFTPOpcode(node yaml.Node) (uint16, error) {
	if node.Kind == 0 {
		return 0, fmt.Errorf("opcode 必填(可用 rrq/wrq/data/ack/error/oack 或数字)")
	}
	if node.Value == "" {
		return 0, fmt.Errorf("opcode 不能为空串(可用 rrq/wrq/data/ack/error/oack 或数字)")
	}
	var n uint64
	if err := node.Decode(&n); err == nil {
		if n > 0xffff {
			return 0, fmt.Errorf("opcode 超出 uint16: %d", n)
		}
		return uint16(n), nil
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return 0, fmt.Errorf("opcode 需要名字或数字: %w", err)
	}
	key := strings.ToLower(strings.TrimSpace(s))
	if v, ok := tftpOpcodeNames[key]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("未知 opcode %q(可用 rrq/wrq/data/ack/error/oack 或数字)", s)
}

// ParseTFTPErrorCode 解析 error 报文的 code 字段:字符串名(大小写不敏感)或数字;
// 未写缺省 0(not_defined,配合自定义 message)。
func ParseTFTPErrorCode(node yaml.Node) (uint16, error) {
	if node.Kind == 0 || node.Value == "" {
		return 0, nil
	}
	var n uint64
	if err := node.Decode(&n); err == nil {
		if n > 0xffff {
			return 0, fmt.Errorf("code 超出 uint16: %d", n)
		}
		return uint16(n), nil
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return 0, fmt.Errorf("code 需要名字或数字: %w", err)
	}
	key := strings.ToLower(strings.TrimSpace(s))
	if v, ok := tftpErrorCodes[key]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("未知 code %q(可用 not_defined/file_not_found/access_violation/disk_full/illegal_operation/unknown_tid/file_exists/no_such_user/option_negotiation 或数字)", s)
}

// validateTFTPFields 按 opcode 做字段约束校验(硬错)。
// 与 opcode 无关的字段不在此拦截——故意写无关字段是合法畸形用例,由 CheckTFTPFieldIgnored 产软告警。
func validateTFTPFields(f *TFTPFields) error {
	op, err := ParseTFTPOpcode(f.Opcode)
	if err != nil {
		return err
	}
	switch op {
	case 1, 2: // rrq / wrq
		if f.Filename == "" {
			return fmt.Errorf("opcode %s 需要 filename(不得为空)", tftpOpcodeName(op))
		}
		return validateTFTPOptions(f.Options, false)
	case 3: // data
		if f.Block == nil {
			return fmt.Errorf("opcode data 需要 block(缺省会静默产出 DATA[0],须显式写)")
		}
		return validateTFTPDataPair(f.Data, f.DataHex)
	case 4: // ack
		if f.Block == nil {
			return fmt.Errorf("opcode ack 需要 block(0 = 确认 WRQ / OACK,但须显式写)")
		}
	case 5: // error
		if _, err := ParseTFTPErrorCode(f.Code); err != nil {
			return err
		}
	case 6: // oack
		// 空 OACK 几乎必是配置错误(RFC 2347 要求至少回显一个选项);
		// 构造空 OACK 畸形包走 payload_hex 兜底通道。
		return validateTFTPOptions(f.Options, true)
	}
	return nil
}

// validateTFTPOptions 校验选项列表:name/value 均非空;
// requireNonEmpty 时空列表也是硬错(oack 至少回显一个选项)。
func validateTFTPOptions(opts []TFTPOption, requireNonEmpty bool) error {
	if len(opts) == 0 {
		if requireNonEmpty {
			return fmt.Errorf("options 至少一个(空 OACK 几乎必是配置错误,构造空 OACK 畸形包请用 payload_hex)")
		}
		return nil
	}
	for i, o := range opts {
		if o.Name == "" {
			return fmt.Errorf("options[%d] 需要 name", i)
		}
		if o.Value == "" {
			return fmt.Errorf("options[%d] 需要 value", i)
		}
	}
	return nil
}

// validateTFTPDataPair 校验 data / data_hex 互斥与 hex 合法性;均空合法(0 字节末块)。
func validateTFTPDataPair(data, dataHex string) error {
	if data != "" && dataHex != "" {
		return fmt.Errorf("data 和 data_hex 只能配置一个")
	}
	if dataHex != "" {
		if _, err := ParsePayloadHex(dataHex); err != nil {
			return err
		}
	}
	return nil
}

// tftpOpcodeName 返回数字 opcode 的规范名,未知数字返回原数字字符串(报错文案用)。
func tftpOpcodeName(op uint16) string {
	for name, v := range tftpOpcodeNames {
		if v == op {
			return name
		}
	}
	return fmt.Sprintf("%d", op)
}

// TFTPDefaultBlockSize 是 RFC 1350 的默认块大小(512 字节)。
const TFTPDefaultBlockSize = 512

// TFTPTransferBlockCount 计算给定数据长度与块大小下需要的 DATA 块数。
// 空数据恰一块(0 字节末块);非空向上取整;恰好整除时额外补一个 0 字节末块,
// 因为接收端靠「末块长度 < block_size」判断传输结束。
func TFTPTransferBlockCount(dataLen, blockSize uint32) uint32 {
	n := (dataLen + blockSize - 1) / blockSize
	if n == 0 {
		n = 1
	}
	if dataLen > 0 && dataLen%blockSize == 0 {
		n++
	}
	return n
}

// validateTFTPTransferFields 校验宏标记字段:data/data_hex 互斥、block_size 显式 0
// 与超限拦截、hex 合法性、块号溢出。
// 位置约束(须在 UDP flow 的 messages[].stack 且唯一一层)由调用方承载。
func validateTFTPTransferFields(f *TFTPTransferFields) error {
	if err := validateTFTPDataPair(f.Data, f.DataHex); err != nil {
		return err
	}
	bs := uint32(TFTPDefaultBlockSize)
	if f.BlockSize != nil {
		if *f.BlockSize == 0 {
			return fmt.Errorf("block_size 须 ≥ 1(缺省 512;显式 0 无法切块)")
		}
		bs = uint32(*f.BlockSize)
	}

	// 在 Validate 阶段拦截块号溢出,validate / generate_yaml 与 gen / generate_pcap 都能早报错。
	data, err := tftpTransferDataBytes(f)
	if err != nil {
		// hex 格式错误已由 validateTFTPDataPair 捕获,理论上不走到这里。
		return err
	}
	if n := TFTPTransferBlockCount(uint32(len(data)), bs); n > 65535 {
		return fmt.Errorf("block_size %d 下需 %d 块,超过块号上限 65535(约 32 MB);请增大 block_size", bs, n)
	}
	return nil
}

// tftpTransferDataBytes 返回宏的传输字节切片,供块数计算使用。
// data / data_hex 互斥由 validateTFTPDataPair 保证。
func tftpTransferDataBytes(f *TFTPTransferFields) ([]byte, error) {
	if f.DataHex != "" {
		return ParsePayloadHex(f.DataHex)
	}
	return []byte(f.Data), nil
}
