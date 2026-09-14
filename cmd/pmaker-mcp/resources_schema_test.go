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

// ---------- 4. 告警 code ⇄ 文档 双向同步 ----------

// TestSchemaWarningCodesSync 锁定「schema 文档承诺的告警 ⇄ 实现 warning code」双向同步:
//   - 正向(实现 → 文档):scenario.WarningCodes() 的每个 code 都须出现在某份 schema 文档里,
//     否则 MCP 客户端拿不到程序化匹配所需的 code 标识符;
//   - 反向(文档 → 实现):文档里以反引号包裹、形如告警 code 的 token(小写点分且含连字符,
//     与 snake_case 字段路径区分)必须是真实存在的 code,否则文档承诺了不存在的告警。
func TestSchemaWarningCodesSync(t *testing.T) {
	codes := scenario.WarningCodes()

	// 正向:每个 code 至少被一份文档提及。
	for _, code := range codes {
		found := false
		for _, name := range schemaDocNames(t) {
			if strings.Contains(schemaDocText(t, name), "`"+code+"`") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("告警 code %q 未在任何 schema 文档中提及:请在该告警所属协议文档的"+
				"「一致性告警」节标注 code(MCP 客户端按 code 程序化匹配 warnings)", code)
		}
	}

	// 反向:文档里形如告警 code 的 token 必须真实存在。
	codeSet := make(map[string]bool, len(codes))
	for _, c := range codes {
		codeSet[c] = true
	}
	for _, name := range schemaDocNames(t) {
		for _, token := range backtickTokens(schemaDocText(t, name)) {
			// 告警 code 的形状:<域>.<kebab-case 问题>(至少一段含连字符)。
			// 字段路径是 snake_case / 无连字符(如 `multipart.boundary`),不会命中。
			if !strings.Contains(token, ".") || !strings.Contains(token, "-") {
				continue
			}
			if !codeSet[token] {
				t.Errorf("schema/%s.md 提及 %q 形如告警 code,但 scenario.WarningCodes() 里不存在:"+
					"要么 code 写错,要么实现缺了这条告警,要么它其实不是 code(那请改写该 token)", name, token)
			}
		}
	}
}

// backtickTokens 提取文本里全部反引号包裹的 token(不含空白的短 token;含空白的
// 内联代码片段不参与告警 code 匹配)。
func backtickTokens(text string) []string {
	var out []string
	// 逐对反引号取内容(Split 后奇数下标是反引号之间的内容)。
	parts := strings.Split(text, "`")
	for i := 1; i+1 < len(parts); i += 2 {
		tok := parts[i]
		if tok == "" || strings.ContainsAny(tok, " \t\r\n/():;=|") {
			continue
		}
		out = append(out, tok)
	}
	return out
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
	for line := range strings.SplitSeq(schemaDocText(t, name), "\n") {
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
