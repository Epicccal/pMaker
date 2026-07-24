# 方案 B:让 plan 支持消息粒度的分步展开

> 本文件用于在**新的 Claude Code session** 中继续推进方案 B。本 session 的对话上下文已不够,
> 请以本文件 + 代码为准。**开工前必读 `CLAUDE.md`(项目根 + `~/.claude/CLAUDE.md`)**。

## 0. 一句话目标

让 FTP 控制通道 ↔ 数据通道这种**消息级双向交错**的 `start_after` 场景,能真正生成 pcap。
方案 A(已合入)只让 `Validate` 不再误拦它;方案 B 要让 `plan.Plan` 真的展开它。

## 1. 背景:为什么需要方案 B

FTP 控制通道与数据通道是两条独立 TCP 五元组流,但应用层时序是**消息级双向交错**:

```
控制通道: ... RETR ─► 150 ─────────────────────► 226 ...
                          │ (150 后开始)         │ (数据传完才发 226)
                          ▼                      ▲
数据通道:                 SYN/SYN-ACK/ACK ─► [文件内容] ─► 挥手
```

期望用**两条独立 flow + 双向 `start_after`** 表达(不引入 `data_connection` 之类新字段):

- 数据通道 flow:`start_after: control.150`(flow 级,锚到控制流 150 报文的 msgCursor)
- 控制通道的 226 报文:`start_after: data`(message 级,锚到数据流整流结束)

时序上无环:150 → 数据通道 → 226 是一条有向链。

## 2. 当前状态(已合入 main,commit `9b449d6`)

### 2.1 方案 A 已完成:校验层放行合法交错

`internal/scenario/validateStartAfter`(scenario.go:654 起)的循环检测已从 **flow 粒度**
改为**事件粒度**:

- 节点 = flow 的起点 / 终点 + 每条参与引用的 message;
- 边 `X→Y` = "X 依赖 Y(X 在 Y 之后)";
- 流内链 `start → msg → ... → end` + 跨流 `start_after` 边落在对应事件节点。

FTP 交错在事件粒度下 `control.150 → ... → control.226` 方向一致、不成环,故 `Validate` 通过。
真环(跨流消息级互引、flow 级自引)仍被三色 DFS 拦截。

新增测试(均绿):
- `TestStartAfterAcceptsFTPStyleInterleave`(load_test.go):FTP 式合法交错应通过 Validate;
- `TestStartAfterMessageLevelCycleRejected`:跨流消息级互引仍被拦。

### 2.2 问题:展开器仍是整流粒度,跑不通

`plan.Plan` + `flow.Expand` 当前以**整条 flow 为原子展开单元**:

- `flow.Expand`(flow.go:86)同步顺序循环,一口气把握手→全部消息→挥手跑完才返回,
  一次性返回 `([]PlannedPacket, flowEnd, msgids)`;
- `plan` 的 `registry` 只在一条 flow **整流展开完毕后**才登记它的 `flowEnd` 与 `msgCursors`
  (plan.go:127);
- `flowDepsResolved`(plan.go:169)判断一条 flow 能否展开,要求它所有被引 flow
  (**flow 级 start_after 的被引 flow + 各 message 级 start_after 的被引 flow**)
  **均已整流入 registry**。

对 FTP 交错这导致**死锁**(互相等对方整流先完成):

- `control.226` message 级 `start_after: data` → 需要 `data` 整流结束入 registry;
- `data` flow 级 `start_after: control.150` → 需要 `control` 整流结束入 registry;
- `control` 整流结束要求 `226` 先展开,`226` 又在等 `data` → `remaining` 永不进展;
- 撞 `if !progress`(plan.go:153)报 `start_after 存在未解析的循环依赖`。

**已验证**:`Validate` 通过,但 `plan.Plan` 报上述错。即校验说合法、展开器说循环,
两条路径对"依赖"粒度判断不一致——方案 B 要填这个缺口。

> 探针:见本文件末尾「附录 A」的临时测试,可直接复现"Validate 过 / Plan 失败"。

## 3. 设计:消息粒度的两段式展开

核心思路:**把"时间计算"与"包生成"解耦**,不再要求被引 flow 整流先完成。

### 3.1 阶段一:算时(只算时刻,不发包)

按事件粒度的**拓扑序**逐个算出每个事件的时刻:

- 输入:方案 A 已能给出的"事件 DAG + 拓扑序"(目前 `validateStartAfter` 只用来检环,
  方案 B 需要把"拓扑序/事件节点"提取为可复用结构,plan 在阶段一直接消费)。
- 对每条 message:`start` = 被引时刻(若 `start_after`)或"上一条消息末尾"(默认链式) + `offset_time`;
  `end` = 该消息整组末尾(各段 + 对端 ACK + DefaultStep),即 msgCursor。
- 对每条 flow:`flowStart`(锚)= base / 被引时刻 + offset;`flowEnd` = 挥手后。
- 输出:一张「事件 → 绝对时刻」表(每个具名 message 的 msgCursor、每条 flow 的 flowStart/flowEnd)。

拓扑序保证:算某事件时,它依赖的事件已算完。FTP:
`control.flowStart`(=base) → `control.150.end` → `data.flowStart` → `data.flowEnd`
→ `control.226.start` → `control.226.end` → `control.flowEnd`。

### 3.2 阶段二:展开(各 flow 拿着已算好的 per-message 时刻独立发包)

`flow.Expand` 改为接收「该 flow 各 message 的起始时刻表」,按表给每条消息定 `start`,
不再依赖运行期 `resolve` 回调去查别的 flow 的 registry(因为时刻已在阶段一算好)。
seq/ack 状态仍在**单次展开内**连续维护(握手/挥手/各消息同一条 conn),不变。
最后 plan 按 `Time` 稳定排序(plan.go:160,已有)输出。

### 3.3 关键约束:确定性 + 零回归

- **逐字节确定性**:同一 scenario + seed 必须产生完全相同的 pcap。不用 `time.Now()`,
  拓扑序按事件节点序稳定推进(不依赖 map 迭代序或 goroutine 真实调度)。
- **零回归**:无跨流 message 交错(含现有全部示例与 golden)时,行为必须与现状逐字节等价。
  `flow.Expand` 现有「链式 msgCursor + resolve 回调」路径应作为退化情形保留,或新路径在无
  交错时产出与旧路径相同的时刻表。**改完务必 `go test ./...` 全绿,golden 逐字节不变。**

## 4. 需要改动的位置(锚点,以当前 main 为准)

| 文件 | 位置 | 现状 | 方案 B 要做 |
|------|------|------|------------|
| `internal/scenario/scenario.go` | `validateStartAfter`(654 起)+ `eventGraph`(840 起) | 事件 DAG 仅用于检环 | 把事件节点/DAG/拓扑序提取为**可复用的导出结构**,供 plan 阶段一直接消费(或新增 `scenario.StartAfterGraph` 之类) |
| `internal/flow/flow.go` | `Expand`(86)、消息循环(114-164)、`resolve` 回调(82-85) | 一次性整流展开 + resolve 回调 | 改为可消费"per-message 起始时刻表"分步展开;保留无交错时的退化等价 |
| `internal/plan/plan.go` | `Plan`(55)、`flowDepsResolved`(169)、多遍展开(133-157)、`registry`(63) | 整流粒度多遍拓扑 | 改两段式:阶段一按事件拓扑算时刻,阶段二各 flow 独立展开;`flowDepsResolved` 退化为"被引事件已算时" |

> 注意:`validateStartAfter` 内部的 `eventGraph`、`active`、节点索引等目前是**包内私有**且
> 与校验耦合。方案 B 要么把它们提升为导出结构,要么在 scenario 包内新增一个
> 「构建事件 DAG + 返回拓扑序」的函数供 plan 调用。**避免在两个包里重复实现图逻辑。**

## 5. 验收标准

1. `go test ./...`(含 `-race`)全绿;`gofmt -l .` / `go vet ./...` 无输出;
2. 现有全部 golden 逐字节不变(确定性 + 零回归);
3. 附录 A 的 FTP 双向交错场景:`Validate` 通过 **且** `plan.Plan` 成功产出包,
   时序正确(`control.150` < 数据通道各包 < `control.226`);
4. 把附录 A 场景沉淀成 `examples/` 示例 + golden + 回读测试(参照现有
   `examples/interleave/message_start_after.yaml` 与 `examples/ftp/control_triggers_data.yaml`
   的风格);
5. 真环(跨流消息级互引)仍在校验阶段被 `validateStartAfter` 拦截,不会走到 plan。

## 6. 已知风险 / 注意点

- **同流 message 级 start_after 仍被一刀切拒**(scenario.go:739-740,`禁止引用本 flow`)。
  事件粒度下,"同流后段引前段"(如 `control.226 start_after control.150`)其实是合法的。
  方案 B 若要支持更自然的同流表达,需评估是否松绑此守卫;**但 FTP 主用例用跨流 `start_after: data`
  绕开了它,故非必须**。若动它,需更新 `TestStartAfterMessageLevelSameFlowRejected`。
- **流内"声明序 = 时间序"是隐式不变式**:方案 A 的图依赖此假设(跨过非参与消息连相邻参与消息
  仍为真实"之后")。`flow.go` 当前 `msgCursor` 每条消息都推进(flow.go:156),保证该不变式。
  方案 B 改 `flow.Expand` 时**不得破坏**它,否则方案 A 的校验图会失真。
- **`flowDepsResolved` 的判定语义要同步降粒度**:从"被引 flow 整流入表"改为"被引事件已算时"。
  否则即便算时阶段做好了,plan 仍可能误判死锁。
- **错误信息可读性**:事件粒度环报错带 `start:`/`end:`/`msg:` 前缀,对非开发者不友好。
  若顺手优化可做 label 美化(非必须)。

## 7. 提交规范(摘自 CLAUDE.md)

- 先建分支再推送(不要直接推 main);建议分支名 `refactor/plan-msg-granularity` 或 `feat/ftp-data-flow`;
- 提交前跑完整测试套件;
- 按逻辑拆分提交(重构 / 测试 / 示例 / 文档各自独立);
- 中文 commit message 与 PR 文案。

---

## 附录 A:复现"Validate 过 / Plan 失败"的探针测试

放 `internal/plan/` 下临时跑(改完方案 B 后此场景应 Plan 成功)。构造已对齐当前类型签名:

```go
package plan_test

import (
	"encoding/hex"
	"testing"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

func planFlow(name, sa string, msgs ...scenario.Message) scenario.FlowSpec {
	return scenario.FlowSpec{
		Name: name, StartAfter: sa,
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 100, ServerISN: 200}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
		},
		Messages: msgs,
	}
}

func msg(from, id, sa string) scenario.Message {
	return scenario.Message{
		From: from, MessageID: id, StartAfter: sa,
		Stack: []scenario.Layer{{Type: "payload_hex",
			Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte("x")))}},
	}
}

func TestFTPBidirectionalPlan(t *testing.T) {
	// control: retr(150 前的请求) → pasv(=150,被 data 引用) → 226(start_after data,等数据传完)
	control := planFlow("control", "",
		msg("src", "retr", ""),
		msg("dst", "pasv", ""),
		msg("dst", "", "data"),
	)
	// data: 整流 start_after control.pasv(150 收完后才开始)
	data := planFlow("data", "control.pasv", msg("src", "", ""))
	s := &scenario.Scenario{LinkType: "ethernet", Seed: 1,
		Flows: []scenario.FlowSpec{control, data}}

	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate 应通过(方案A 已放行): %v", err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan 应成功(方案B 目标),实失败: %v", err) // 当前 main 在此失败
	}
	t.Logf("Plan 成功,共 %d 包", len(planned))
	// 期望:control.150 的包时刻 < data 的包时刻 < control.226 的包时刻
}
```

> 当前 main 行为:`Validate` 通过,`plan.Plan` 报
> `start_after 存在未解析的循环依赖(应在校验阶段拦截)`。方案 B 完成后此测试应通过。

## 附录 B:相关历史分支(参考,勿直接 merge)

- `feat/ftp-data-connection`(本地):FTP 控制连接 + 用 `data_connection` **新字段**嵌套子会话的
  旧实现。merge-base 早于 start_after/PlannedPacket 时间编排,无法直接 merge。其 FTP 控制连接
  序列化逻辑(`serializeFTPReq/Resp`)与示例可参考。用户明确目标:**不引入新字段**,故数据通道
  走「独立 flow + 双向 start_after」,而非 `data_connection`。
