# tftp_transfer —— TFTP 文件传输宏(仅 UDP flow 的 messages)

不是协议层,而是 message 级**宏标记**:一条 `tftp_transfer` 消息在展开期自动降解成
DATA[1..n] / ACK[1..n] 若干条普通 `tftp` 消息(DATA 从声明方发出,对端逐块 ACK),
展开后 flow / plan / builder 全部不感知宏的存在。这是 UDP 会话不变式
「一条 message = 一个 UDP 数据报」下的正确分层:TFTP 分块是**应用层成帧**
(块号 + ACK 锁步),不是传输层切片,不能复用 `segment`。通则见
`pmaker://schema/_conventions`。

**只能出现在 UDP flow 的 `messages[].stack` 里,且须是该消息唯一的一层**;
standalone `packets`、`flow.stack`、TCP flow、与其它层共存都会被硬拒。
单条报文(含畸形)用普通 `tftp` 层手写,见 `pmaker://schema/tftp`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: tftp-req
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 50001, dport: 69 }
      - udp_session: {}
    messages:
      - from: src
        message_id: rrq
        stack:
          - tftp:
              opcode: rrq
              filename: "bigfile.bin"
              mode: octet
              options:
                - { name: blksize, value: "1024" }

  - name: tftp-data
    start_after: tftp-req.rrq
    stack:
      - eth:         { src: "00:11:22:33:44:02", dst: "00:11:22:33:44:01" }
      - ipv4:        { src: "10.0.0.2", dst: "10.0.0.1", ttl: 64 }
      - udp:         { sport: 55000, dport: 50001 }
      - udp_session: {}
    messages:
      - from: src                  # 宏消息:DATA 从 src(服务器)发,ACK 从 dst 回
        message_id: xfer
        stack:
          - tftp_transfer:
              data: "content of bigfile"
              block_size: 1024
              interval: "+2ms"
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `data` | string | 与 `data_hex` 二选一 | 文件内容(文本);支持 `@file(path)` 注入外部文件原始字节 |
| `data_hex` | string | 与 `data` 二选一 | `0x…` 原始字节(二进制内容) |
| `block_size` | uint16 | 否 | 块大小,缺省 512(RFC 1350);显式 0 硬错。应与 RRQ/OACK 协商的 blksize 一致,工具不跨包核对 |
| `interval` | Offset | 否 | 每条 ACK 与后续 DATA 相对上一条消息末尾的间隔,缺省紧接(+1ms);`0s` = 紧接 |

## 展开规则

- 块数 n = ⌈len / block_size⌉;**len 恰为 block_size 整数倍时补一个 0 字节末块**
  (接收端靠「末块长度 < block_size」判断结束),空数据也是恰一个 0 字节块。
- 块号 1..n 递增,超过 65535 硬错(约 32 MB 上限,请增大 block_size)。
- DATA 的 `from` 继承宏消息声明,ACK 取反;DATA 块全部落 `data_hex` 字节。
- 宏的 `message_id` 挂在**最后一条 ACK** 上(整组完成语义,`start_after` 引用从这里起算);
  `offset_time` / `start_after` 挂在 DATA[1] 上(起点 = 第一块)。
- `interval` 是每条 ACK 与后续 DATA 的 `offset_time`;缺省走消息默认链式接续(1ms)。

## 静默陷阱

- **block_size 须与协商一致**:RRQ/OACK 里声明的 blksize 选项与宏的 `block_size`
  是两处独立声明,工具不跨包核对 —— 写不一致会产出「协商 1024 实际按 512 切」的
  静默坏包,接收端结束判定直接失灵。
- **方向语义**:RRQ 场景 DATA 从**服务器**发(宏消息 `from: src` 指数据 flow 的 src,
  即服务器);WRQ 场景反过来。照抄示例时先确认数据方向。
- **宏不产畸形**:块号跳变、丢 ACK、重复块、超长块等畸形序列须手写普通 `tftp` 报文
  (或 flow messages),宏只会产出规范的锁步序列。

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `tftp_transfer 只能作为 UDP flow 的 messages[].stack 的唯一一层` | 位置不对:不能进 standalone `packets` / `flow.stack` / `quote.stack`;单条报文用普通 `tftp` 层 |
| `tftp_transfer 只能用于 UDP flow` | TFTP 是 UDP 原生协议,TCP flow 无意义;改 `udp` + `udp_session` |
| `tftp_transfer 须是该消息唯一的一层` | 宏消息不能与其它层共存(如 OACK、ACK[0] 须各自独立成 message) |
| `data 和 data_hex 只能配置一个` | 文本内容用 `data`(可 `@file`),二进制用 `data_hex`,二选一 |
| `block_size 须 ≥ 1` | 显式 0 无法切块;缺省 512,想自定义写 ≥ 1 的值 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 40000, dport: 69 }
      - tftp_transfer: { data: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: tcp-xfer
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:         { sport: 40001, dport: 69 }
      - tcp_session: {}
    messages:
      - from: src
        stack:
          - tftp_transfer: { data: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: mixed-stack
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 40002, dport: 69 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - tftp:         { opcode: oack, options: [{ name: blksize, value: "512" }] }
          - tftp_transfer: { data: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: bad-bs
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 40003, dport: 69 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - tftp_transfer: { data: "hi", block_size: 0 }
```

```yaml-bad
link_type: ethernet
flows:
  - name: both-data
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 40004, dport: 69 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - tftp_transfer: { data: "hi", data_hex: "0x01" }
```

## 相关

`pmaker://schema/tftp`(单条报文层与 wire 格式)、`pmaker://schema/udp_session`
(UDP 会话与端口切换模式)、`pmaker://schema/overview`(messages / 时间编排)
