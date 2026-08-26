package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCmdValidateValidYAML 对合法场景 cmdValidate 应返回 0。
func TestCmdValidateValidYAML(t *testing.T) {
	rc := cmdValidate([]string{"-f", "../../examples/http/get.yaml"})
	if rc != 0 {
		t.Errorf("合法场景应返回 0,得到 %d", rc)
	}
}

// TestCmdValidateInvalidYAML 对非法场景 cmdValidate 应返回 1。
func TestCmdValidateInvalidYAML(t *testing.T) {
	// tcp 缺 sport/dport,Validate 应报错。
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(`link_type: ethernet
seed: 42
packets:
  - stack:
      - eth: { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp: { flags: [SYN] }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := cmdValidate([]string{"-f", path})
	if rc != 1 {
		t.Errorf("非法场景应返回 1,得到 %d", rc)
	}
}

// TestCmdValidateMissingFlag 缺 -f 应返回 2(用法错误)。
func TestCmdValidateMissingFlag(t *testing.T) {
	rc := cmdValidate(nil)
	if rc != 2 {
		t.Errorf("缺 -f 应返回 2,得到 %d", rc)
	}
}

// TestCmdValidateMissingFile 指向不存在的文件应返回 1(Load 失败)。
func TestCmdValidateMissingFile(t *testing.T) {
	rc := cmdValidate([]string{"-f", filepath.Join(t.TempDir(), "nope.yaml")})
	if rc != 1 {
		t.Errorf("不存在文件应返回 1,得到 %d", rc)
	}
}

// TestCmdGenProducesNonEmptyPcap cmdGen 出包到临时目录,校验文件非空。
func TestCmdGenProducesNonEmptyPcap(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.pcap")
	rc := cmdGen([]string{"-f", "../../examples/http/get.yaml", "-o", out})
	if rc != 0 {
		t.Fatalf("合法场景应返回 0,得到 %d", rc)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("输出文件应存在: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("输出 pcap 不应为空")
	}
	// pcap 文件头魔数:a1b2c3d4(微秒)或 a1b2cd34(nano)的小端/大端形式。
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 4 {
		t.Fatal("pcap 文件头应至少 4 字节")
	}
	// 大端 magic 0xa1b2c3d4,小端则是同字节序翻转;取前 4 字节判断是否任一已知魔数。
	magic := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	switch magic {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b2cd34, 0x34cdb2a1:
	default:
		t.Errorf("pcap 魔数不对: %08x", magic)
	}
}

// TestCmdGenMissingFlags 缺 -f 或 -o 应返回 2。
func TestCmdGenMissingFlags(t *testing.T) {
	if rc := cmdGen([]string{"-o", filepath.Join(t.TempDir(), "x.pcap")}); rc != 2 {
		t.Errorf("缺 -f 应返回 2,得到 %d", rc)
	}
	if rc := cmdGen([]string{"-f", "../../examples/http/get.yaml"}); rc != 2 {
		t.Errorf("缺 -o 应返回 2,得到 %d", rc)
	}
}

// TestCmdGenInvalidScenario 非法场景应返回 1(不在输出路径写文件)。
func TestCmdGenInvalidScenario(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(`link_type: ethernet
seed: 42
packets:
  - stack:
      - eth: { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp: { flags: [SYN] }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.pcap")
	rc := cmdGen([]string{"-f", path, "-o", out})
	if rc != 1 {
		t.Errorf("非法场景应返回 1,得到 %d", rc)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("非法场景不应写输出文件")
	}
}
