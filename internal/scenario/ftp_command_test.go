package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 ftp_command.go 的 FTP 命令名 / 响应码合法基线校验:
// 已知命令(大小写不敏感)、三位响应码(100-599)、未知值报错并引导 payload / payload_hex。
// 与 DNS 枚举校验风格对齐:结构化字段只接合法基线,非标值走原始字节通道。

// ftpLayer 包装一条 ftp_request 层,便于表驱动构造。
func ftpLayer(cmd, args string) scenario.Layer {
	return scenario.Layer{Type: "ftp_request", Fields: &scenario.FTPRequestFields{Command: cmd, Args: args}}
}

// ftpRespLayer 包装一条 ftp_response 层。
func ftpRespLayer(code int, msg string) scenario.Layer {
	return scenario.Layer{Type: "ftp_response", Fields: &scenario.FTPResponseFields{Code: code, Message: msg}}
}

// baseStack 是承载 FTP 校验的最小合法 stack(eth/ipv4/tcp),供包内测试直接构造 Scenario。
func baseStack(layer scenario.Layer) []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 21}},
		layer,
	}
}

// TestValidateFTPCommand_KnownAccepts: RFC 959 核心与常见扩展命令均通过(大小写不敏感)。
func TestValidateFTPCommand_KnownAccepts(t *testing.T) {
	for _, cmd := range []string{"USER", "user", "RETR", "retr", "PASV", "FEAT", "AUTH", "MLSD", "EPSV", "QUIT"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpLayer(cmd, ""))}}}
		if err := scenario.Validate(s); err != nil {
			t.Errorf("已知命令 %q 应通过,得到: %v", cmd, err)
		}
	}
}

// TestValidateFTPCommand_UnknownRejects: 拼写错误(如 RETER)与非标命令报错,
// 错误信息引导改用 payload / payload_hex。
func TestValidateFTPCommand_UnknownRejects(t *testing.T) {
	for _, cmd := range []string{"RETER", "reter", "XYZW", "FOO"} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpLayer(cmd, ""))}}}
		err := scenario.Validate(s)
		if err == nil {
			t.Fatalf("未知命令 %q 应被拒,实际通过", cmd)
		}
		if !strings.Contains(err.Error(), cmd) {
			t.Errorf("错误应点名命令 %q,得到: %v", cmd, err)
		}
		if !strings.Contains(err.Error(), "payload") || !strings.Contains(err.Error(), "payload_hex") {
			t.Errorf("错误应引导 payload / payload_hex,得到: %v", err)
		}
	}
}

// TestValidateFTPCommand_EmptyRejects: 空命令报错。
func TestValidateFTPCommand_EmptyRejects(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpLayer("", ""))}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("空 command 应报错,得到: %v", err)
	}
}

// TestValidateFTPResponseCode_ValidAccepts: 100-599 范围内的合法码通过。
func TestValidateFTPResponseCode_ValidAccepts(t *testing.T) {
	for _, code := range []int{100, 200, 220, 227, 331, 421, 530, 599} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpRespLayer(code, "msg"))}}}
		if err := scenario.Validate(s); err != nil {
			t.Errorf("合法响应码 %d 应通过,得到: %v", code, err)
		}
	}
}

// TestValidateFTPResponseCode_OutOfRangeRejects: 22 / 99 / 600 / 负数等非法位数报错。
func TestValidateFTPResponseCode_OutOfRangeRejects(t *testing.T) {
	for _, code := range []int{0, 22, 99, 600, 1000, -1} {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpRespLayer(code, "msg"))}}}
		err := scenario.Validate(s)
		if err == nil {
			t.Fatalf("非法响应码 %d 应被拒,实际通过", code)
		}
		if !strings.Contains(err.Error(), "100-599") {
			t.Errorf("错误应提示范围 100-599,得到: %v", err)
		}
	}
}

// TestValidateFTPResponse_MessageOrLinesRequired: code 合法但缺 message/lines 仍报错。
func TestValidateFTPResponse_MessageOrLinesRequired(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: baseStack(ftpRespLayer(220, ""))}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "message") {
		t.Fatalf("合法 code 但缺 message/lines 应报错,得到: %v", err)
	}
}
