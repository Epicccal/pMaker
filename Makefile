# pMaker Makefile —— 一键构建 pmaker(CLI)与 pmaker-mcp(MCP server)
#
# 设计要点(与 .goreleaser.yml、CLAUDE.md 对齐):
#   - 纯 Go,CGO_ENABLED=0,静态编译,跨平台开箱即用。
#   - -trimpath 去除本机路径,ldflags -s -w 去除调试信息、注入版本号到 main.version。
#   - 版本号优先取 git 描述(tag),无 tag 时退化为 commit 短哈希;脱离 git 仓库时为 "dev"。
#
# 常用:
#   make            # 构建两个二进制到 bin/
#   make build      # 同上
#   make pmaker     # 只构建 CLI
#   make mcp        # 只构建 MCP server
#   make test       # 跑完整测试
#   make quality    # gofmt + go vet + go test(提交前质量门禁)
#   make clean      # 清理 bin/ 与覆盖率文件

# ===== 可覆盖变量 =====

# 输出目录
BIN_DIR ?= bin

# 版本号:优先 git 描述,失败退化为 dev。
# shell 内 `||` 保证脱离 git 仓库(或无 git)时仍能取到 "dev"。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Go 构建参数
CGO_ENABLED ?= 0
GOFLAGS     := -trimpath
LDFLAGS     := -s -w -X main.version=$(VERSION)

# 目标二进制
BIN_PMMAKER := $(BIN_DIR)/pmaker
BIN_MCP     := $(BIN_DIR)/pmaker-mcp

# ===== 默认目标 =====

.PHONY: all build pmaker mcp clean test test-v test-files race cover vet fmt lint quality run help

all: build

build: pmaker mcp

# ===== 构建规则 =====

# 两个二进制共享同构的构建逻辑,用同一份 recipe + target-specific 变量。
# BUILD_MAIN / BUILD_BIN 由各目标就近绑定。
$(BIN_PMMAKER): main_cmd := ./cmd/pmaker
$(BIN_MCP):     main_cmd := ./cmd/pmaker-mcp

# 模式规则:任何 bin/<name> 都从对应变量指定的 main 包构建。
# 因为 $(BIN_*) 各自绑定了 main_cmd,make 会按文件名匹配本规则。
$(BIN_DIR)/%:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ $(main_cmd)

pmaker: $(BIN_PMMAKER)
	@echo "✓ 已构建 $<  (version=$(VERSION))"

mcp: $(BIN_MCP)
	@echo "✓ 已构建 $<  (version=$(VERSION))"

# ===== 测试与质量门禁 =====

test:
	go test ./...

# 详细模式:每个测试函数单独一行,带 -v 看逐个文件/用例的运行情况。
test-v:
	go test -v ./...

# 逐文件测试:对每个有测试文件(含外部 _test 包)的目录单独运行 go test,逐行打印文件路径与结果。
# 用 .TestGoFiles 或 .XTestGoFiles 探测,以覆盖 flow/plan 这种只有 test_only 包的情况。
test-files:
	@for d in $$(go list -f '{{ if or .TestGoFiles .XTestGoFiles }}{{ .Dir }}{{ end }}' ./...); do \
		pkg=$$(cd "$$d" && go list .); \
		echo "→ $$(basename $$d)  ($$d)"; \
		( cd "$$d" && go test . 2>&1 | grep -E '^(ok|FAIL|---|===)' ) || exit 1; \
	done

race:
	go test -race ./...

cover:
	go test -cover ./...

vet:
	go vet ./...

# gofmt 只列出不符合规范的文件,应无输出。
fmt:
	@gofmt -l .
	@if [ -z "$$(gofmt -l .)" ]; then echo "✓ gofmt 通过"; else echo "✗ 上述文件需 gofmt -w"; exit 1; fi

# golangci-lint 若已安装则运行,否则跳过并提示。
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠ 未安装 golangci-lint,已跳过(可选: https://golangci-lint.run)"; \
	fi

# 提交前质量门禁:gofmt + vet + test,对应 CLAUDE.md「提交前必跑」。
quality: fmt vet test
	@echo "✓ 质量门禁通过"

# ===== 辅助 =====

# 用一个示例场景快速冒烟验证 CLI 能出包。
run: pmaker
	./$(BIN_PMMAKER) gen -f examples/http/get.yaml -o /tmp/pmaker-smoke.pcap && \
		echo "✓ 已生成 /tmp/pmaker-smoke.pcap"

clean:
	@rm -rf $(BIN_DIR) coverage.out
	@echo "✓ 已清理 $(BIN_DIR)/ 与 coverage.out"

help:
	@echo "pMaker Makefile —— 目标:"
	@echo "  make            构建两个二进制到 bin/(pmaker + pmaker-mcp)"
	@echo "  make build      同上"
	@echo "  make pmaker     只构建 CLI"
	@echo "  make mcp        只构建 MCP server"
	@echo "  make test       跑完整测试(包级汇总)"
	@echo "  make test-v     详细模式,逐个用例打印"
	@echo "  make test-files 逐文件跑测试,打印每个文件路径与结果"
	@echo "  make race       带竞态检测的测试"
	@echo "  make cover      带覆盖率的测试"
	@echo "  make vet        go vet ./..."
	@echo "  make fmt        检查 gofmt(不修改)"
	@echo "  make lint       golangci-lint(未安装则跳过)"
	@echo "  make quality    gofmt + vet + test(提交前门禁)"
	@echo "  make run        构建并用示例场景冒烟出包"
	@echo "  make clean      清理 bin/ 与 coverage.out"
	@echo ""
	@echo "可覆盖变量:VERSION=\$$(git describe)、BIN_DIR=bin、CGO_ENABLED=0"
