package main

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件是 schema 文档的**测试锁**:把「文档与实现同步」从人肉硬约束变成 CI 约束。
// 三条锁分别对应设计方案的三类漂移:
//   - TestSchemaLayerCoverage  层名 ⇄ 文档 双向对应(加层忘写文档 / 删层留下孤儿文档)
//   - TestSchemaSnippetsValid  文档里的 YAML 片段真能跑(例子写错 / 实现改了语义)
//   - TestSchemaErrorTextsExist 「报错 → 改法」表左列确实是校验器原文(校验器改措辞)
//
// fence 约定(文档作者须遵守):
//
//	```yaml         完整 scenario,须过 Parse+Validate;若在「## 骨架」节下另须 Warnings 为空
//	```yaml-bad     故意违规,须报错;其 error 文本是「报错 → 改法」表的取证来源
//	```yaml-sketch  带 ... 的结构示意(仅 overview 用),跳过
//	```text / 无标签 wire 字节示意等,跳过

// nonLayerSchemaDocs 是 schema/ 下**不对应任何层**的文档:通则、总览、子结构。
// 除此之外任何 `_` 前缀文件(设计立场 `_why_*`)也不参与覆盖性比对。
var nonLayerSchemaDocs = map[string]bool{
	"overview":  true, // 入口导读,不是层
	"multipart": true, // 子结构(嵌在 http_*/eml_data 内),不能写进 stack
}

// pendingSnippetFiles 列出尚未按新 fence 约定重写的 schema 文档。
// 它们的 ```yaml fence 目前多是片段(如 `- eth: { ... }`)而非完整 scenario,
// 过不了 Parse+Validate,故整文件跳过。
//
// 批次 ④ 每重写一个文件就删掉对应一行;清空后连同本变量与下方的跳过分支一并删除。
var pendingSnippetFiles = map[string]bool{
	"dns":           true,
	"eml_data":      true,
	"eth":           true,
	"ftp_request":   true,
	"ftp_response":  true,
	"gre":           true,
	"http_request":  true,
	"http_response": true,
	"icmp":          true,
	"icmp6":         true,
	"icmpv6":        true,
	"imap_request":  true,
	"imap_response": true,
	"ipv4":          true,
	"ipv6":          true,
	"multipart":     true,
	"overview":      true,
	"payload":       true,
	"payload_hex":   true,
	"pop3_request":  true,
	"pop3_response": true,
	"smtp_request":  true,
	"smtp_response": true,
	"tcp":           true,
	"tcp_session":   true,
	"telnet":        true,
	"udp":           true,
	"vlan":          true,
}

// ---------- 1. 覆盖性:层名 ⇄ 文档 ----------

func TestSchemaLayerCoverage(t *testing.T) {
	docs := schemaDocNames(t)
	layers := scenario.LayerTypes()

	// 正向:每个合法层名都要有文档(否则 pmaker://schema/<层> 是 404)。
	for _, layer := range layers {
		if !slices.Contains(docs, layer) {
			t.Errorf("层 %q 有实现但无 schema 文档:请加 resources/schema/%s.md", layer, layer)
		}
	}
	// 反向:每份文档要么是层,要么在非层名单/`_` 前缀里(否则是删层留下的孤儿)。
	for _, doc := range docs {
		if slices.Contains(layers, doc) || nonLayerSchemaDocs[doc] || strings.HasPrefix(doc, "_") {
			continue
		}
		t.Errorf("文档 %s.md 不对应任何层:若是层请在 scenario.layerDecoders 登记,"+
			"若非层请加进 nonLayerSchemaDocs", doc)
	}
}

// ---------- 2. 片段可执行 ----------

func TestSchemaSnippetsValid(t *testing.T) {
	for _, name := range schemaDocNames(t) {
		if pendingSnippetFiles[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			for _, f := range schemaFences(t, name) {
				err := parseAndValidate(f.body)
				switch f.tag {
				case "yaml":
					if err != nil {
						t.Errorf("%s 第 %d 行的 ```yaml 片段应合法,却报错: %v", name, f.line, err)
						continue
					}
					if f.section != "骨架" {
						continue
					}
					// 骨架是模型最可能原样复制的东西,带软告警的骨架会把告警扩散进所有下游场景。
					s, _ := scenario.Parse([]byte(f.body), t.TempDir())
					if ws := scenario.Warnings(s); len(ws) > 0 {
						t.Errorf("%s 第 %d 行的骨架不应有软告警,得到: %v", name, f.line, ws)
					}
				case "yaml-bad":
					if err == nil {
						t.Errorf("%s 第 %d 行的 ```yaml-bad 片段应报错,却通过了校验", name, f.line)
					}
				}
			}
		})
	}
}

// ---------- 3. 「报错 → 改法」表左列取证 ----------

func TestSchemaErrorTextsExist(t *testing.T) {
	for _, name := range schemaDocNames(t) {
		wants := errorTableSnippets(t, name)
		if len(wants) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			// 取证来源只有本文件的 yaml-bad fence:不额外维护第二份错误文案清单。
			var got []string
			for _, f := range schemaFences(t, name) {
				if f.tag != "yaml-bad" {
					continue
				}
				if err := parseAndValidate(f.body); err != nil {
					got = append(got, err.Error())
				}
			}
			for _, want := range wants {
				if !slices.ContainsFunc(got, func(e string) bool { return strings.Contains(e, want) }) {
					t.Errorf("%s「报错 → 改法」表里的 %q 不是任何 yaml-bad 片段的真实报错:\n"+
						"要么它已不是校验器原文(校验器改了措辞),"+
						"要么该行缺一个能触发它的 ```yaml-bad fence。实际报错:%v", name, want, got)
				}
			}
		})
	}
}

// ---------- 辅助 ----------

// parseAndValidate 把片段当完整 scenario 走一遍解析 + 语义校验。
// baseDir 取空串:文档片段不该依赖外部文件(@file 的演示写在散文里,不进 fence)。
func parseAndValidate(body string) error {
	s, err := scenario.Parse([]byte(body), "")
	if err != nil {
		return err
	}
	return scenario.Validate(s)
}

// schemaDocNames 返回 embed 的 schema 目录下全部文档名(去掉 .md),按字典序。
func schemaDocNames(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(schemaFS, "resources/schema")
	if err != nil {
		t.Fatalf("读 embed schema 目录: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, strings.TrimSuffix(e.Name(), ".md"))
		}
	}
	slices.Sort(names)
	return names
}

func schemaDocText(t *testing.T, name string) string {
	t.Helper()
	data, err := schemaFS.ReadFile("resources/schema/" + name + ".md")
	if err != nil {
		t.Fatalf("读 schema/%s.md: %v", name, err)
	}
	return string(data)
}

// fence 是文档里一段代码围栏。section 记录它所属的最近一个 `## ` 标题,
// 用于区分「骨架」节(须无告警)与其它节。
type fence struct {
	tag     string
	section string
	line    int // 围栏起始行号(1-based),报错定位用
	body    string
}

// schemaFences 提取一份文档里的全部代码围栏。
// 只认行首的 ``` 围栏(markdown 表格/散文里的行内反引号不受影响)。
func schemaFences(t *testing.T, name string) []fence {
	t.Helper()
	var out []fence
	var section string
	var cur *fence
	var body []string
	for i, line := range strings.Split(schemaDocText(t, name), "\n") {
		if cur == nil {
			if rest, ok := strings.CutPrefix(line, "```"); ok {
				cur = &fence{tag: strings.TrimSpace(rest), section: section, line: i + 1}
				body = nil
				continue
			}
			if rest, ok := strings.CutPrefix(line, "## "); ok {
				section = strings.TrimSpace(rest)
			}
			continue
		}
		if strings.HasPrefix(line, "```") {
			cur.body = strings.Join(body, "\n")
			out = append(out, *cur)
			cur = nil
			continue
		}
		body = append(body, line)
	}
	if cur != nil {
		t.Errorf("schema/%s.md 第 %d 行的代码围栏未闭合", name, cur.line)
	}
	return out
}

// errorTableSnippets 提取「## 报错 → 改法」节下 markdown 表格的左列内容
// (去掉包裹的反引号),即「必须是校验器 error 真实子串」的那些片段。
func errorTableSnippets(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	inSection := false
	for _, line := range strings.Split(schemaDocText(t, name), "\n") {
		if rest, ok := strings.CutPrefix(line, "## "); ok {
			inSection = strings.HasPrefix(strings.TrimSpace(rest), "报错")
			continue
		}
		if !inSection {
			continue
		}
		cell, ok := firstTableCell(line)
		if !ok {
			continue
		}
		// 跳过表头行与 |---|---| 分隔行。
		if strings.Contains(cell, "报错") || strings.Trim(cell, "-: ") == "" {
			continue
		}
		out = append(out, cell)
	}
	return out
}

// firstTableCell 取 markdown 表格行的第一个单元格内容(去掉反引号与空白)。
// 非表格行返回 ok=false。
func firstTableCell(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		return "", false
	}
	cells := strings.Split(strings.Trim(trimmed, "|"), "|")
	if len(cells) == 0 {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(cells[0]), "`"), true
}
