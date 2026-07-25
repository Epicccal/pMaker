package scenario_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
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
