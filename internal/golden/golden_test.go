package golden_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExamplesGolden 把 examples/<协议>/ 下每个 YAML 都作为正式测试用例。
// 子目录按协议组织(icmp/icmpv6/http/dns/ipv6/tunnel ...),golden 镜像到
// testdata/<协议>/<name>.pcap,避免跨协议同名文件冲突。
// 新增示例时,这里会自动要求生成对应的 golden。
func TestExamplesGolden(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../examples", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("examples 目录下没有 yaml 用例")
	}

	for _, src := range files {
		// 子测试名用相对 examples/ 的路径(去扩展名),如 "icmp/echo"。
		rel, err := filepath.Rel("../../examples", src)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.ToSlash(strings.TrimSuffix(rel, filepath.Ext(rel)))
		t.Run(name, func(t *testing.T) {
			got := generatePcap(t, src)
			golden := filepath.Join("testdata", name+".pcap")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("读取 golden 失败(首次请加 -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("与 golden 不一致(%d vs %d 字节)", len(got), len(want))
			}
		})
	}
}
