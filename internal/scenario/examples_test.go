package scenario_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

var update = flag.Bool("update", false, "regenerate golden pcap files")

// TestExamplesGolden 把 examples/ 下每个 YAML 都作为正式测试用例。
// 新增示例时,这里会自动要求生成对应的 testdata/<name>.pcap。
func TestExamplesGolden(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("examples 目录下没有 yaml 用例")
	}

	for _, src := range files {
		name := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
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

func TestHTTPKeepaliveLFIContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http_keepalive_lfi.yaml")
	for _, want := range [][]byte{
		[]byte("GET /robots.txt HTTP/1.1"),
		[]byte("HTTP/1.1 404 Not Found"),
		[]byte("GET /../etc/passwd HTTP/1.1"),
		[]byte("root:x:0:0:root:/root:/bin/bash"),
		[]byte("hab:x:1000:1000::/home/hab:/usr/bin/zsh"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Fatalf("pcap 不含 %q", want)
		}
	}
}

func generatePcap(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	for _, f := range s.Flows {
		pkts, err := flow.Expand(f)
		if err != nil {
			t.Fatalf("expand %s: %v", path, err)
		}
		s.Packets = append(s.Packets, pkts...)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return buf.Bytes()
}
