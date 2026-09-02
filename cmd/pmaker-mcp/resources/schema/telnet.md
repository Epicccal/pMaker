# telnet —— TELNET 事件(L7,走 tcp)

一个 `telnet` 层 = 一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本),序列化为 TCP payload。
多事件:同段内层栈重复多个 `telnet` 层拼接;跨段用 flow `messages`。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: telnet-negotiate
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.23", ttl: 64 }
      - tcp:  { sport: 49152, dport: 23, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - telnet: { command: WILL, option: SGA }
      - from: dst
        stack:
          - telnet: { command: DO, option: SGA }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | 名称 / 数字 | 否 | WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR;空 = 纯 NVT 文本(须有 `args`/`args_hex`) |
| `option` | 名称 / 数字 | 条件 | option 码(已知名或十进制/0x 数字);仅协商(WILL/WONT/DO/DONT)与 SB 用 |
| `args` | string | 条件 | 文本(SB subneg 内容或 NVT 文本);字面 0xFF 自动转义为 IAC IAC;与 `args_hex` 互斥 |
| `args_hex` | string | 条件 | `0x…` 二进制原始字节(如 NAWS),不转义;与 `args` 互斥 |

`command` / `option` 校验对齐 DNS 模式:已知名(大小写不敏感)或数字;未知**名字**报错并引导 `payload`/`payload_hex`。

**已知 command**:WILL/WONT/DO/DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR。
**已知 option**:BINARY(0)/ECHO(1)/SGA(3)/STATUS(5)/TM(6)/TSPEED(8)/TTYPE(24)/EOR(25)/NAWS(31)/LINEMODE(34)/OLD_ENVIRON(36)/NEW_ENVIRON(39)。

## 组合规则

- `args` 与 `args_hex` 互斥,至多其一。
- **二字节控制命令**(GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR):仅 `IAC + cmd`,禁带 `option` / `args` / `args_hex`。
- **协商**(WILL/WONT/DO/DONT):`IAC + cmd + option`,必带 `option`,禁带 `args` / `args_hex`。
- **SB**(subnegotiation):`IAC SB opt 内容 IAC SE`,必带 `option` 与 `args`/`args_hex` 之一作内容。
- 纯 NVT 文本(`command` 空):须有 `args`/`args_hex`,禁带 `option`。

## 静默陷阱

- **TTYPE SB 的 `args` 会被自动前缀 `IS` 限定符**:写 `command: SB, option: TTYPE, args: XTERM`
  产出 `IAC SB TTYPE IS XTERM IAC SE`(builder 自动加 `IS` 字节)。要发 `SEND`(无终端名)
  必须用 `args_hex: "0x01"` 显式表达 —— 写 `args` 永远是 `IS`+名。
- **NAWS 等二进制 subneg 必须用 `args_hex`**:NAWS 是 4 字节大端宽高(`0x00500018` = 80×24),
  写 `args` 会触发 IAC 转义,把 0xFF 字节转义掉,产出错误字节且无告警。
- **NVT 文本的裸 CR 被自动归一为 CR NUL**:`args` 里的裸 `\r`(后非 `\n`)变成 `\r\0`(RFC 854 §2),
  `CR LF` 原样保留。这是合规归一,但若你想要"裸 CR 不带 NUL"的畸形形态,用 `args_hex`。
- **`command` / `option` 的数字不做语义校验**:`command: "200"`、`option: "200"` 照单全收
  (私有码模糊测试),但拼错的**名字**(`wil`)会报错。`option` 数字回退与 `command` 数字回退都支持。
- SB 内容是 option 专有二进制,**不套** NVT 的 CR NUL 归一(只做 IAC 转义);NVT 文本才套。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非标 IAC 序列、未转义 0xFF | `payload` / `payload_hex` |
| 私有 / 未列入 option 码 | `option: "200"`(数字) |
| NAWS 等二进制 subneg | `args_hex: "0x00500018"` |
| TTYPE SEND(无终端名) | `args_hex: "0x01"` |
| 裸 CR 不带 NUL | `args_hex`(绕过 NVT 归一) |
| 非标 subneg 内容(无 IS 限定符) | `args_hex`(绕过 TTYPE 自动 IS 前缀) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `args 与 args_hex 只能配置一个` | 文本与原始字节二选一。二进制 subneg 用 `args_hex` |
| `WILL 必须带 option` | 协商命令(WILL/WONT/DO/DONT)与 SB 都要带 `option` |
| `控制命令 "GA" 不带 option` | 二字节控制命令禁带 `option` / `args`,把它们删掉 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 23, flags: [PSH, ACK] }
      - telnet: { command: WILL, args: "x", args_hex: "0x01" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 23, flags: [PSH, ACK] }
      - telnet: { command: WILL }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 23, flags: [PSH, ACK] }
      - telnet: { command: GA, option: ECHO }
```

## 相关

`pmaker://schema/tcp_session`、`pmaker://schema/payload_hex`、`pmaker://examples`
