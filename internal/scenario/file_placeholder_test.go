package scenario

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestExpandString 覆盖占位符解析的各分支:单/多占位符、前后缀拼接、@@ 转义、裸 @、绝对与相对路径、二进制内容。
func TestExpandString(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "hello.txt"), []byte("world"))
	mustWrite(t, filepath.Join(dir, "bin.dat"), []byte{0x00, 0x01, 0x02, 0xff})

	cases := []struct {
		name    string
		s       string
		want    string
		wantErr string
	}{
		{"无占位符", "plain text", "plain text", ""},
		{"单占位符", "@file(hello.txt)", "world", ""},
		{"前缀+占位符", "pre-@file(hello.txt)-post", "pre-world-post", ""},
		{"多占位符", "@file(hello.txt)@file(hello.txt)", "worldworld", ""},
		{"多占位符夹文本", "a=@file(hello.txt);b=@file(hello.txt)", "a=world;b=world", ""},
		{"二进制内容", "x@file(bin.dat)y", "x\x00\x01\x02\xffy", ""},
		{"@@转义为@", "a@@b", "a@b", ""},
		{"@@file整体转义", "@@file(hello.txt)", "@file(hello.txt)", ""},
		{"裸@保留(email)", "user@host.com", "user@host.com", ""},
		{"空路径报错", "@file()", "", "路径为空"},
		{"缺右括号报错", "@file(hello.txt", "", "缺少右括号"},
		{"文件不存在报错", "@file(no-such.txt)", "", "no-such.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandString(tc.s, dir)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("期望报错含 %q,得到 nil(err),结果=%q", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("错误 %q 不含 %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("未期望报错: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expandString(%q)= %q (bytes=%x),期望 %q (bytes=%x)", tc.s, got, []byte(got), tc.want, []byte(tc.want))
			}
		})
	}
}

// TestExpandStringAbsPathInsideBaseDir baseDir 内的绝对路径可用(仍是常见写法:
// 用户把绝对路径指向 workdir/scenario 目录内的文件)。
func TestExpandStringAbsPathInsideBaseDir(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "abs.txt")
	mustWrite(t, abs, []byte("ABS"))
	got, err := expandString("@file("+abs+")", dir)
	if err != nil {
		t.Fatalf("baseDir 内绝对路径应可用: %v", err)
	}
	if got != "ABS" {
		t.Fatalf("绝对路径结果=%q,期望 ABS", got)
	}
}

// TestExpandStringAbsPathOutsideBaseDir baseDir 外的绝对路径硬错(安全限制:
// MCP 部署下场景 YAML 来自远端模型,任意绝对路径读取是可被提示注入利用的读原语)。
func TestExpandStringAbsPathOutsideBaseDir(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir() // 另一个无关目录
	abs := filepath.Join(outside, "secret.txt")
	mustWrite(t, abs, []byte("SECRET"))
	_, err := expandString("@file("+abs+")", dir)
	if err == nil {
		t.Fatal("baseDir 外绝对路径应报错")
	}
	if !strings.Contains(err.Error(), "越出 baseDir") {
		t.Fatalf("错误 %q 不含 \"越出 baseDir\"", err.Error())
	}
}

// TestExpandStringRelativeEscape 相对路径用 ../ 逃出 baseDir 硬错。
func TestExpandStringRelativeEscape(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secret.txt"), []byte("SECRET"))
	// baseDir = dir/sub,../secret.txt 逃到 dir 下
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := expandString("@file(../secret.txt)", sub); err == nil {
		t.Fatal("../ 逃出 baseDir 应报错")
	} else if !strings.Contains(err.Error(), "越出 baseDir") {
		t.Fatalf("错误 %q 不含 \"越出 baseDir\"", err.Error())
	}
}

// TestExpandStringSymlinkEscape baseDir 内指向外部的符号链接不能绕过包含性检查
// (检查基于 EvalSymlinks 后的真实路径)。
func TestExpandStringSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("符号链接在 Windows 上需要特权,跳过")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	mustWrite(t, secret, []byte("SECRET"))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	_, err := expandString("@file(link.txt)", dir)
	if err == nil {
		t.Fatal("指向 baseDir 外的符号链接应报错")
	}
	if !strings.Contains(err.Error(), "越出 baseDir") {
		t.Fatalf("错误 %q 不含 \"越出 baseDir\"", err.Error())
	}
}

// TestExpandStringSymlinkInside baseDir 内指向 baseDir 内部目标的符号链接正常读。
func TestExpandStringSymlinkInside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("符号链接在 Windows 上需要特权,跳过")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	mustWrite(t, target, []byte("REAL"))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got, err := expandString("@file(link.txt)", dir)
	if err != nil {
		t.Fatalf("baseDir 内符号链接应可用: %v", err)
	}
	if got != "REAL" {
		t.Fatalf("符号链接结果=%q,期望 REAL", got)
	}
}

// TestExpandStringRelativeFromBaseDir 相对路径相对 baseDir 解析。
func TestExpandStringRelativeFromBaseDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "sub", "rel.txt"), []byte("REL"))
	// baseDir = dir,路径 "sub/rel.txt" → dir/sub/rel.txt
	got, err := expandString("@file(sub/rel.txt)", dir)
	if err != nil {
		t.Fatalf("相对路径解析失败: %v", err)
	}
	if got != "REL" {
		t.Fatalf("相对路径结果=%q,期望 REL", got)
	}
}

// TestExpandFilePlaceholdersWalksScenario 反射遍历覆盖各结构位置:
// 顶层、packet.stack[].fields、flow.stack、flow.messages[].stack、map(header 值)、嵌套 quote 包。
func TestExpandFilePlaceholdersWalksScenario(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "body.txt"), []byte("BODY"))
	mustWrite(t, filepath.Join(dir, "pay.txt"), []byte("PAY"))
	mustWrite(t, filepath.Join(dir, "hdr.txt"), []byte("HDR"))
	mustWrite(t, filepath.Join(dir, "ftp.txt"), []byte("RETR x"))
	mustWrite(t, filepath.Join(dir, "quote.txt"), []byte("QUOTED"))

	// link_type 也会被遍历(无 @ 快路径跳过),确认不误伤。
	s := &Scenario{
		LinkType: "ethernet",
		Packets: []Packet{{
			Name: "p1",
			Stack: []Layer{
				{Type: "eth", Fields: &EthFields{Src: "a", Dst: "b"}},
				{Type: "payload", Fields: &PayloadFields{Payload: "@file(pay.txt)"}},
			},
		}},
		Flows: []FlowSpec{{
			Name: "f",
			Stack: []Layer{
				{Type: "eth", Fields: &EthFields{Src: "a", Dst: "b"}},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
				{Type: "tcp", Fields: &TCPFields{SPort: 1, DPort: 2}},
				{Type: "tcp_session", Fields: &TCPSessionFields{}},
			},
			Messages: []Message{{
				From: "src",
				Stack: []Layer{
					{Type: "http_request", Fields: &HTTPReqFields{
						Method:  "POST",
						Headers: HeaderMap{{Key: "X-Custom", Value: "@file(hdr.txt)"}},
						Body:    "@file(body.txt)",
					}},
				},
			}, {
				From: "src",
				Stack: []Layer{
					{Type: "ftp_request", Fields: &FTPRequestFields{Command: "@file(ftp.txt)"}},
				},
			}},
		}},
	}

	if err := ExpandFilePlaceholders(s, dir); err != nil {
		t.Fatalf("ExpandFilePlaceholders: %v", err)
	}

	if got := s.Packets[0].Stack[1].Fields.(*PayloadFields).Payload; got != "PAY" {
		t.Errorf("packet payload = %q,期望 PAY", got)
	}
	msg0 := s.Flows[0].Messages[0].Stack[0].Fields.(*HTTPReqFields)
	if got := msg0.Body; got != "BODY" {
		t.Errorf("http body = %q,期望 BODY", got)
	}
	if got, ok := msg0.Headers.Get("X-Custom"); !ok || got != "HDR" {
		t.Errorf("header X-Custom = %q(ok=%v),期望 HDR", got, ok)
	}
	msg1 := s.Flows[0].Messages[1].Stack[0].Fields.(*FTPRequestFields)
	if got := msg1.Command; got != "RETR x" {
		t.Errorf("ftp command = %q,期望 'RETR x'", got)
	}
}

// TestExpandFilePlaceholdersQuoteNested 嵌套 quote 包(ICMP quote_from)内的 @file 也被遍历。
func TestExpandFilePlaceholdersQuoteNested(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "inner.txt"), []byte("INNER"))

	s := &Scenario{
		Packets: []Packet{{
			Stack: []Layer{
				{Type: "icmp", Fields: &ICMPFields{
					Type: scalarNode("echo_request"),
					Quote: &Packet{Stack: []Layer{
						{Type: "ipv4", Fields: &IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
						{Type: "payload", Fields: &PayloadFields{Payload: "@file(inner.txt)"}},
					}},
				}},
			},
		}},
	}
	if err := ExpandFilePlaceholders(s, dir); err != nil {
		t.Fatalf("ExpandFilePlaceholders: %v", err)
	}
	quote := s.Packets[0].Stack[0].Fields.(*ICMPFields).Quote
	if got := quote.Stack[1].Fields.(*PayloadFields).Payload; got != "INNER" {
		t.Errorf("嵌套 quote payload = %q,期望 INNER", got)
	}
}

// TestExpandFilePlaceholdersSkipsYAMLNode ICMPFields.Type 是 yaml.Node,
// 不应被替换(其内部 Value 字段不含 @file 时也无影响;含 @file 也不替换)。
func TestExpandFilePlaceholdersSkipsYAMLNode(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "t.txt"), []byte("REPLACED"))
	s := &Scenario{
		Packets: []Packet{{
			Stack: []Layer{
				{Type: "icmp", Fields: &ICMPFields{
					Type:    scalarNode("@file(t.txt)"),
					Payload: "@file(t.txt)",
				}},
			},
		}},
	}
	if err := ExpandFilePlaceholders(s, dir); err != nil {
		t.Fatalf("ExpandFilePlaceholders: %v", err)
	}
	icmp := s.Packets[0].Stack[0].Fields.(*ICMPFields)
	// yaml.Node 的 Value 不被替换
	if got := icmp.Type.Value; got != "@file(t.txt)" {
		t.Errorf("yaml.Node.Value 被错误替换为 %q(应跳过 yaml.Node)", got)
	}
	// 但普通 string 字段 Payload 被替换
	if got := icmp.Payload; got != "REPLACED" {
		t.Errorf("ICMP Payload = %q,期望 REPLACED", got)
	}
}

// scalarNode 把字符串包成 yaml.Node(scalar),用于测试中需要 yaml.Node 字段的场景。
func scalarNode(s string) yaml.Node {
	return yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
