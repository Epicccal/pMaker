package scenario_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
	"gopkg.in/yaml.v3"
)

// TestPayloadHexRequiresPrefix 校验 ParsePayloadHex(见 types.go)对 0x 前缀的强制要求,
// 并覆盖 validateLayer 对 payload_hex 标量层的校验路径。
func TestPayloadHexRequiresPrefix(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		got, err := scenario.ParsePayloadHex("0xdeadbeef")
		if err != nil {
			t.Fatalf("ParsePayloadHex failed: %v", err)
		}
		if len(got) != 4 || got[0] != 0xde || got[1] != 0xad || got[2] != 0xbe || got[3] != 0xef {
			t.Fatalf("unexpected bytes: %x", got)
		}
	})

	t.Run("missing-prefix", func(t *testing.T) {
		if _, err := scenario.ParsePayloadHex("deadbeef"); err == nil {
			t.Fatal("expected error for payload_hex without 0x prefix")
		}
	})

	t.Run("yaml-validate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		data := []byte("packets:\n  - stack:\n      - payload_hex: deadbeef\n")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write temp yaml: %v", err)
		}
		s, err := scenario.Load(path)
		if err != nil {
			t.Fatalf("load yaml: %v", err)
		}
		if err := scenario.Validate(s); err == nil {
			t.Fatal("expected validate error for payload_hex without 0x prefix")
		}
	})
}

// TestHexRejectsNegative:Hex 字段都是无符号 wire 值,负数与超 uint32 上限直接拒绝,
// 不得静默回绕/截断(int64 解码 + uint32 截断会把 key: -1 变成 0xffffffff、
// key: 4294967296 变成 0x0,后者还会绕过 validateLengthRange 的位宽检查)。
func TestHexRejectsNegative(t *testing.T) {
	// 直测 UnmarshalYAML:任一 Hex 字段同一类型,取 gre.key 做代表
	unmarshal := func(doc string) error {
		var s struct {
			Key scenario.Hex `yaml:"key"`
		}
		return yaml.Unmarshal([]byte(doc), &s)
	}
	t.Run("十进制负数拒绝", func(t *testing.T) {
		err := unmarshal("key: -1")
		if err == nil || !strings.Contains(err.Error(), "非负整数") {
			t.Fatalf("key: -1 应报非负整数错误,得到: %v", err)
		}
	})
	t.Run("十六进制负数拒绝", func(t *testing.T) {
		err := unmarshal(`key: "-0x1"`)
		if err == nil {
			t.Fatal(`key: "-0x1" 应报错(ParseUint 不接受负号,旧路径同样拒绝,此处锁行为)`)
		}
	})
	t.Run("超 uint32 上限拒绝(截断防线)", func(t *testing.T) {
		// 4294967296 = 0x100000000:截断成 0 后 gre.protocol 的 16 位检查形同虚设
		for _, doc := range []string{"key: 4294967296", "key: 0x100000000"} {
			err := unmarshal(doc)
			if err == nil || !strings.Contains(err.Error(), "0xFFFFFFFF") {
				t.Fatalf("%s 应报超上限错误,得到: %v", doc, err)
			}
		}
	})
	t.Run("非负十进制与 0x 均放行", func(t *testing.T) {
		for _, doc := range []string{"key: 42", "key: 0xdead", `key: "0xdead"`, "key: 0", "key: 4294967295"} {
			if err := unmarshal(doc); err != nil {
				t.Fatalf("%s 应放行,得到: %v", doc, err)
			}
		}
	})
}
