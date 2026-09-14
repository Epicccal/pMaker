package scenario

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// 文件占位符:@file(<path>) 在 Parse 阶段被替换为对应文件的原始字节。
//
// 设计要点(见 CLAUDE.md「文件占位符 @file」):
//
//   - 替换发生在 YAML decode 之后:先让 yaml.v3 把字段解成 Go string,再扫描 string 值里的
//     @file(...)。文件可能为二进制(非 UTF-8),不能在 YAML 文本层替换——否则破坏 YAML 语法。
//     Go 的 string 本质是 []byte,能存任意字节;后续 builder 转 []byte 写包无障碍。
//   - 生效范围:全部 string 字段(反射遍历 Scenario 递归替换)。故 @file 可写在 body、payload、
//     header 值、ftp args、ICMP payload 等任意内容字段里,文件可只占字段值的一部分(前后可带其它
//     文本,可多个 @file 拼接)。结构字段(layer.type、from、MAC/IP)写 @file 会被同样替换,
//     进而破坏生成——这是用户自找,机制保持纯净不拦截。
//   - 路径解析:绝对路径与相对路径一律须落在 baseDir 之内(CLI 传 scenario 文件所在目录,
//     MCP 传 workdir),越界硬错。baseDir 是唯一的信任边界:MCP 部署下场景 YAML 由远端模型
//     生成,放任任意路径读取会构成可被提示注入利用的任意文件读取原语(且告警文本会回显内容)。
//   - 转义:@@ → 字面 @;其余裸 @ 原样保留(不报错,兼容 email 等 @ 语义)。
//   - payload_hex 是 hex 编码字段,@file 注入原始字节会破坏 hex 语义——二进制内容请用 payload。
//   - 确定性:文件内容固定 → 同 scenario 同输入 → 逐字节相同 pcap。被引文件需随场景一起归档
//     (与 golden pcap 就近放 testdata 同理),否则换机器不可复现。

const (
	filePlaceholderPrefix = "@file("
)

// yamlNodeType 是 yaml.Node 的 reflect.Type,用于在反射遍历时跳过(不递归、不替换):
// yaml.Node 的 Value/Tag/Anchor 等内部 string 字段不应被占位符替换。
var yamlNodeType = reflect.TypeFor[yaml.Node]()

// ExpandFilePlaceholders 遍历 s 的所有 string 字段,把 @file(<path>) 替换为文件内容。
// baseDir 是相对路径的基准目录(通常为 scenario 文件所在目录)。
func ExpandFilePlaceholders(s *Scenario, baseDir string) error {
	return walkStrings(reflect.ValueOf(s).Elem(), baseDir, "")
}

// walkStrings 递归遍历 v,对其所有可设置的 string 字段执行占位符替换。
// path 是当前值在 Scenario 结构中的字段路径(用于错误定位,如 "Packets[0].Stack[0].Fields.Body")。
//
// 对 HeaderEntry(HeaderMap 的元素):只替换 Value、不替换 Key
// (HTTP headers 的 key 是结构字段,不应被 @file 改写)。
func walkStrings(v reflect.Value, baseDir, path string) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		if !v.CanSet() {
			return nil
		}
		old := v.String()
		if !strings.Contains(old, "@") {
			return nil // 快路径:无 @ 直接跳过(MAC/IP/type 等绝大多数字段)
		}
		expanded, err := expandString(old, baseDir)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if expanded != old {
			v.SetString(expanded)
		}
		return nil
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		if v.Elem().Type() == yamlNodeType {
			return nil // 跳过 yaml.Node
		}
		return walkStrings(v.Elem(), baseDir, path)
	case reflect.Struct:
		if v.Type() == yamlNodeType {
			return nil // 跳过 yaml.Node
		}
		// HeaderMap 的元素 HeaderEntry 只替换 Value、不替换 Key(key 是结构字段)。
		if v.Type() == reflect.TypeFor[HeaderEntry]() {
			return walkStrings(v.FieldByName("Value"), baseDir, joinPath(path, "Value"))
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			fp := joinPath(path, f.Name)
			if err := walkStrings(v.Field(i), baseDir, fp); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fp := fmt.Sprintf("%s[%d]", path, i)
			if err := walkStrings(v.Index(i), baseDir, fp); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}

// expandString 把 s 里的 @file(<path>) 替换为文件内容、@@ 替换为字面 @,其余原样保留。
// 路径不可含右括号 ')'(以第一个 ')' 闭合);需要含 ')' 请改用绝对路径并避开该限制。
func expandString(s, baseDir string) (string, error) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '@' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// s[i] == '@'
		if i+1 < len(s) && s[i+1] == '@' {
			// @@ → 字面 @
			b.WriteByte('@')
			i += 2
			continue
		}
		if strings.HasPrefix(s[i:], filePlaceholderPrefix) {
			start := i + len(filePlaceholderPrefix)
			end := strings.IndexByte(s[start:], ')')
			if end < 0 {
				return "", fmt.Errorf("@file( 缺少右括号 ')'")
			}
			rel := s[start : start+end]
			if rel == "" {
				return "", fmt.Errorf("@file() 路径为空")
			}
			data, err := readFilePlaceholder(rel, baseDir)
			if err != nil {
				return "", err
			}
			b.Write(data)
			i = start + end + 1
			continue
		}
		// 裸 @(非 @@ 非 @file():兼容 email 等含 @ 的普通文本),原样保留
		b.WriteByte('@')
		i++
	}
	return b.String(), nil
}

// readFilePlaceholder 按 baseDir 解析路径并读文件,最终路径必须落在 baseDir 之内:
// 相对路径 Join 后 Clean;绝对路径也须位于 baseDir 下(用 EvalSymlinks 解析符号链接,
// 防 workdir 内的软链指向外部 + /tmp 类共享目录符号链接绕过)。越界返回硬错(带改法)。
func readFilePlaceholder(rel, baseDir string) ([]byte, error) {
	// 符号链接解析:包含性检查基于真实路径,否则 workdir 内指向外部的软链可逃逸。
	// EvalSymlinks 要求路径存在,顺带替代了 ReadFile 的存在性检查语义。
	// baseDir 先 Abs(CLI 可能传相对路径,如 "examples/http"),之后 Join 出的 p 必为
	// 绝对路径;EvalSymlinks 解析 baseDir 与 p 本身的符号链接(如 macOS /tmp → /private/tmp),
	// 包含性比较才不失真。real 只能通过 baseDir 之内的真实路径,越界硬错(带改法)。
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("@file(%s): 解析 baseDir %s 失败: %w", rel, baseDir, err)
	}
	p := rel
	if !filepath.IsAbs(p) {
		p = filepath.Join(baseAbs, p)
	}
	p = filepath.Clean(p)
	baseAbs, err = filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return nil, fmt.Errorf("@file(%s): 解析 baseDir %s 失败: %w", rel, baseDir, err)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, fmt.Errorf("@file(%s): %w", rel, err)
	}
	if real != baseAbs && !strings.HasPrefix(real, baseAbs+string(filepath.Separator)) {
		return nil, fmt.Errorf(
			"@file(%s): 路径 %s 越出 baseDir %s(安全限制:@file 只能读 baseDir 内的文件;"+
				"请把文件放进 baseDir,或把 baseDir 指到包含它的上层目录)",
			rel, real, baseAbs)
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, fmt.Errorf("@file(%s): %w", rel, err)
	}
	return data, nil
}
