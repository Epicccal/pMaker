package scenario

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AbsTime 是绝对时刻,仅 base_time 使用:场景里唯一的绝对锚,各 offset_time 的参考点
// 最终都溯源到它。按 UTC 解析 ISO8601/RFC3339(如 2024-01-01T00:00:00Z),也兼容
// 2024-01-01、2024-01-01 00:00:00 等宽松写法;写成形如 "+1s" 的偏移会在解析阶段失败。
type AbsTime struct {
	t time.Time
}

// UnmarshalYAML 把标量解析为绝对时刻(按 UTC;见 parseAbsTime 支持的格式)。
func (a *AbsTime) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("base_time 需为字符串(如 2024-01-01T00:00:00Z): %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("base_time 不能为空")
	}
	abs, err := parseAbsTime(s)
	if err != nil {
		return fmt.Errorf("非法绝对时刻 %q(如 2024-01-01T00:00:00Z): %w", s, err)
	}
	a.t = abs
	return nil
}

// Time 返回解析后的绝对时刻。
func (a *AbsTime) Time() time.Time { return a.t }

// Offset 是非负时长偏移:packet.offset_time(相对上一包)、flow.offset_time(相对 base_time)、
// message.offset_time(相对上一条消息末尾)、segment.interval(同消息各数据段间隔)使用——
// 参考点因字段而异(见各字段注释与 internal/plan / internal/flow)。
// 仅接受非负时长(如 +1.5s / 500ms / 0s);负值与绝对时刻均在解析阶段失败——
// 负偏移通常意味着 base_time 选错了起点(应把 base_time 提前,而非用负 offset 够到零点之前)。
type Offset struct {
	d time.Duration
}

// UnmarshalYAML 把标量解析为时长偏移。
func (o *Offset) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("offset_time 需为字符串(时长偏移): %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("offset_time 不能为空")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("非法时长偏移 %q(如 +1.5s / 500ms / 0s): %w", s, err)
	}
	if d < 0 {
		return fmt.Errorf("时长偏移 %q 不能为负(若需早于 base_time,请把 base_time 提前)", s)
	}
	o.d = d
	return nil
}

// Duration 返回解析后的偏移时长。
func (o *Offset) Duration() time.Duration { return o.d }

// parseAbsTime 按 RFC3339Nano(及若干常见 layout)解析绝对时刻。
func parseAbsTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析为时间")
}
