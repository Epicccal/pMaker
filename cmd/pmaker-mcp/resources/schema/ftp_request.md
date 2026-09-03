# ftp_request —— FTP 控制连接命令(L7,走 tcp)

一条命令 = 一个 `ftp_request` 层,序列化为 TCP payload `COMMAND[ arg]\r\n`。
同段多条命令就重复写本层;跨段时序用 flow 的 `messages`。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: ftp-user
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.21", ttl: 64 }
      - tcp:  { sport: 49152, dport: 21, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - ftp_request: { command: USER, args: anonymous }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | string | **是** | RFC 959 核心 + 常见扩展(大小写不敏感);未列入报错并引导 `payload`/`payload_hex` |
| `args` | string | 否 | 命令参数(如 `USER` 的用户名、`RETR` 的路径);为空时不追加空格 |

`command` 原样输出(不强制大写),可构造小写 / 非标命令等畸形用例。

**已知命令**:RFC 959 核心(USER/PASS/ACCT/CWD/CDUP/SMNT/QUIT/REIN/PORT/PASV/TYPE/STRU/MODE/
RETR/STOR/STOU/APPE/ALLO/REST/RNFR/RNTO/ABOR/DELE/RMD/MKD/PWD/LIST/NLST/SITE/SYST/STAT/HELP/NOOP)
+ 常见扩展(FEAT/OPTS/AUTH/PBSZ/PROT/MLSD/MLST/MDTM/SIZE/HOST/CLNT/MFMT/CCC/EPRT/EPSV)。

## 组合规则

- `command` 非空且在已知表内;未知命令(含私有命令)报错,改走 `payload` / `payload_hex`。
- `args` 不做内容校验(可含空格、任意字符);要构造 CRLF 注入等多命令行畸形走 `payload_hex`。
- `ftp_request` 是 payload 生产层,可进 `flow.messages`,也可在 standalone `packets` 里用。

## 静默陷阱

- **`args` 不拦换行符**:写 `args: "a\r\nRETR x"` 会产出两行命令字节,校验器不报错。
  这是可用的注入构造点,也是易误踩点;若不是有意注入,别在 `args` 里放 `\r\n`。
- **PORT / EPRT / PASV / EPSV 的端口协商一致性只告警、不拦**:控制通道声明的数据连接端点
  与实际数据流 dst 不一致时产软告警(见 `pmaker://schema/overview` 的 warnings),包照出。
  故意构造不一致是合规的流量验证用例。
- 命令名拼错(如 `RETER`)是**硬错**而非静默降级 —— 这点与 `dns.type` 的数字兜底不同,
  `ftp_request.command` 无数字写法。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 私有 / 非标命令 | `payload` / `payload_hex` |
| 小写 / 混合大小写命令 | `command: user`(原样输出) |
| CRLF 注入(一条命令层产多行) | `args` 带 `\r\n`,或整段 `payload_hex` |
| 协商端口与数据流故意不一致 | 照常写,会出现软告警,包照出 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 command` | `command` 必填。要发裸字节(无命令名)走 `payload` / `payload_hex` |
| `未知 FTP 命令` | 命令不在已知表内。私有 / 非标命令改用 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.21" }
      - tcp:  { sport: 49152, dport: 21, flags: [PSH, ACK] }
      - ftp_request: { args: anonymous }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.21" }
      - tcp:  { sport: 49152, dport: 21, flags: [PSH, ACK] }
      - ftp_request: { command: RETER }
```

## 相关

`pmaker://schema/ftp_response`、`pmaker://schema/tcp_session`、`pmaker://schema/payload_hex`、`pmaker://examples`
