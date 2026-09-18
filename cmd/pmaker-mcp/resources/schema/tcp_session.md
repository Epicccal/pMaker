# tcp_session —— TCP 会话控制(仅 flow.stack)

不是真实协议层,而是告诉 flow 展开器如何补握手 / 挥手。**只能出现在 `flows[].stack` 里**,
standalone `packets` 写它会被拒。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: minimal
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:         { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "ping\n" }
      - from: dst
        stack:
          - payload: { payload: "pong\n" }
```

## 字段

| 字段 | 值 | 说明 |
|------|------|------|
| `open` | `handshake`(缺省)/ `none` | `handshake` 前插 SYN → SYN,ACK → ACK;`none` 假设已建连,直接发数据 |
| `close` | `fin`(缺省)/ `rst` / `none` | `fin` 四次挥手;`rst` 对端单包中断;`none` 不收尾(半开连接) |

两个字段都可省略(`- tcp_session: {}` = `handshake` + `fin`)。

## 组合规则(硬错)

- `flow.stack` **必须**同时含 `eth`、恰好一个网络层(`ipv4` 或 `ipv6`)、`tcp`、`tcp_session`;
  可选夹多层 `vlan`(802.1Q/QinQ,须在 eth 与网络层之间)。
- `open` / `close` 只认上表的字符串;拼错会被拒(不会静默降级)。
- 每条 message 的 `from` 只能是 `src` / `dst`,`stack` 须至少一个 payload 生产层。

## 静默陷阱

- **`open: none` 时 seq 起点仍是 `client_isn` / `server_isn`**,不会自动偏移到"已传过若干字节"的位置。
  想模拟中途抓包,得自己把 ISN 写成目标值。
- **挥手不受 `messages` 影响**:`close: fin` 一定接在最后一条消息之后。要构造"数据未发完就 FIN"
  只能用 `close: none` + `packets` 补包,或整流手写。
- 展开器在每条 message 的最后一段后 **+1ms 插一个对端纯 ACK**,这是硬编码行为:延迟 ACK、
  累积 ACK、丢 ACK 都无法配置。
- 重传 / 乱序 / 重叠段 / IP 分片**均未实现**,写 `segment.order`、`segment.retransmit` 会被
  未知字段校验拒掉;需要这些就用 `packets` 逐包手写 seq。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 半开连接(有握手无收尾) | `close: none` |
| 连接被重置 | `close: rst` |
| 中途抓包(无握手) | `open: none` + 自定 `client_isn` / `server_isn` |
| SYN 洪水 / 只有 SYN 的扫描 | 不用 flow,用 `packets` + `offset_time` 逐包写 |
| 错误的 seq/ack、重传、乱序 | `packets` 逐包写 `seq` / `ack` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `tcp_session.open 只能是 handshake/none` | 只有这两个值。"已建连"写 `none`,不是 `established`/`skip` |
| `tcp_session.close 只能是 fin/rst/none` | 只有这三个值。半关闭、乱序挥手请用 `packets` 逐包写 |
| `stack 需要 tcp 层` | `flow.stack` 必须在单段栈或 VXLAN inner 段包含 `tcp` + `tcp_session`。UDP 会话请用 `udp_session`(见 `pmaker://schema/udp_session`) |
| `会话层与传输层不匹配` | `tcp_session` 前一层须是 `tcp`;UDP 会话改用 `udp_session`(见 `pmaker://schema/udp_session`) |

```yaml-bad
link_type: ethernet
flows:
  - name: bad-open
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:         { sport: 49152, dport: 80 }
      - tcp_session: { open: established }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: bad-close
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:         { sport: 49152, dport: 80 }
      - tcp_session: { close: half }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: no-tcp
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:         { sport: 49152, dport: 53 }
      - tcp_session: { open: handshake }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: no-transport
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp_session: { open: handshake }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

## 相关

`pmaker://schema/tcp`、`pmaker://schema/overview`(flow / messages / segment / 时间编排)
