package builder

import (
	"encoding/hex"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// tftp 层的逐字节编码测试。wire 格式见 tftp.go 头注释。
// 端到端字节比对见 internal/golden;字段约束的硬错矩阵见 internal/scenario。

// node 造一个字符串标量的 yaml.Node(模拟 YAML 解码产物,ParseTFTPOpcode 吃这个)。
func node(s string) yaml.Node {
	return yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

// numNode 造一个整数标量的 yaml.Node。
func numNode(i int) yaml.Node {
	n := node("")
	n.Tag = "!!int"
	n.Value = intStr(i)
	return n
}

func intStr(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

// u16 造 *uint16。
func u16(v uint16) *uint16 { return &v }

// hexStr 是 0x 前缀的十六进制(测试期望值书写用)。
func hexStr(b []byte) string { return "0x" + hex.EncodeToString(b) }

func TestSerializeTFTPRRQ(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("rrq"), Filename: "file.txt"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// 0x0001 + "file.txt" + NUL + "octet"(缺省)+ NUL
	want, _ := hex.DecodeString("0001" + hex.EncodeToString([]byte("file.txt")) + "00" + hex.EncodeToString([]byte("octet")) + "00")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPWRQMode(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("wrq"), Filename: "f", Mode: "netascii"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0002" + hex.EncodeToString([]byte("f")) + "00" + hex.EncodeToString([]byte("netascii")) + "00")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPRQOptions(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{
		Opcode: node("rrq"), Filename: "big.bin", Mode: "octet",
		Options: []scenario.TFTPOption{
			{Name: "blksize", Value: "1024"},
			{Name: "tsize", Value: "0"},
		},
	})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0001" +
		hex.EncodeToString([]byte("big.bin")) + "00" + hex.EncodeToString([]byte("octet")) + "00" +
		hex.EncodeToString([]byte("blksize")) + "00" + hex.EncodeToString([]byte("1024")) + "00" +
		hex.EncodeToString([]byte("tsize")) + "00" + hex.EncodeToString([]byte("0")) + "00")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPData(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("data"), Block: u16(1), Data: "hello"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0003" + "0001" + hex.EncodeToString([]byte("hello")))
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPDataZeroBlock(t *testing.T) {
	// 畸形:DATA[0](block 显式 0)
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("data"), Block: u16(0), Data: "x"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0003" + "0000" + hex.EncodeToString([]byte("x")))
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPDataHex(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("data"), Block: u16(2), DataHex: "0xdeadbeef"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0003" + "0002" + "deadbeef")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPACK(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("ack"), Block: u16(0)})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0004" + "0000")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPError(t *testing.T) {
	// 字符串名 code
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("error"), Code: node("file_not_found"), Message: "no such file"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0005" + "0001" + hex.EncodeToString([]byte("no such file")) + "00")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}

	// 数字 code(畸形通道,255 等透传)
	got, err = serializeTFTP(&scenario.TFTPFields{Opcode: node("error"), Code: numNode(8)})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ = hex.DecodeString("0005" + "0008" + "00") // 无 message:NUL 终止空串
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPOACK(t *testing.T) {
	got, err := serializeTFTP(&scenario.TFTPFields{
		Opcode: node("oack"),
		Options: []scenario.TFTPOption{
			{Name: "blksize", Value: "1024"},
			{Name: "tsize", Value: "4096"},
		},
	})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0006" +
		hex.EncodeToString([]byte("blksize")) + "00" + hex.EncodeToString([]byte("1024")) + "00" +
		hex.EncodeToString([]byte("tsize")) + "00" + hex.EncodeToString([]byte("4096")) + "00")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPUnknownOpcode(t *testing.T) {
	// 数字 opcode 7:只写 2 字节头,无载荷
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: numNode(7)})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if hexStr(got) != "0x0007" {
		t.Fatalf("wire = %s, want 0x0007", hexStr(got))
	}
}

func TestSerializeTFTPEmptyData(t *testing.T) {
	// 0 字节末块:data/data_hex 均空
	got, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("data"), Block: u16(3)})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want, _ := hex.DecodeString("0003" + "0003")
	if hexStr(got) != hexStr(want) {
		t.Fatalf("wire = %s, want %s", hexStr(got), hexStr(want))
	}
}

func TestSerializeTFTPBadOpcode(t *testing.T) {
	if _, err := serializeTFTP(&scenario.TFTPFields{Opcode: node("invalid")}); err == nil {
		t.Fatal("未知字符串 opcode 应报错")
	}
	if _, err := serializeTFTP(&scenario.TFTPFields{}); err == nil {
		t.Fatal("缺 opcode 应报错")
	}
}
