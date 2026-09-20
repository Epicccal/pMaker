# tftp —— TFTP 报文(L7,UDP 数据报)

一个 `tftp` 层 = 一条完整 TFTP 报文(2 字节 opcode + 按 opcode 的载荷)。五种报文
(RRQ / WRQ / DATA / ACK / ERROR)加 RFC 2347 的 OACK 共用一个层,由 `opcode` 分派
—— 与 `icmp` 的 `type` 同构。TFTP 是 UDP 原生协议,通常进 UDP flow 的 `messages`
(端口切换用两条 flow + `start_after`,见「静默陷阱」);批量文件内容用
`tftp_transfer` 宏自动展开,单条报文(含畸形)用本层手写。通则见
`pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: tftp-req
    stack:
      - eth:         { src: "00:11:22:33:44:01", dst: "00:11:22:33:44:02" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:         { sport: 50000, dport: 69 }
      - udp_session: {}
    messages:
      - from: src
        message_id: rrq
        stack:
          - tftp: { opcode: rrq, filename: "hello.txt", mode: octet }

  - name: tftp-data
    start_after: tftp-req.rrq      # RRQ 发出后服务器从新 TID 回复
    stack:
      - eth:         { src: "00:11:22:33:44:02", dst: "00:11:22:33:44:01" }
      - ipv4:        { src: "10.0.0.2", dst: "10.0.0.1", ttl: 64 }
      - udp:         { sport: 54321, dport: 50000 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - tftp: { opcode: data, block: 1, data: "Hello, TFTP!" }
      - from: dst
        stack:
          - tftp: { opcode: ack, block: 1 }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `opcode` | 名称 / 数字 | **是** | `rrq`(1)/ `wrq`(2)/ `data`(3)/ `ack`(4)/ `error`(5)/ `oack`(6),或任意数字(≤0xffff,原样落 wire,构造未知 opcode 畸形) |
| `filename` | string | rrq/wrq **是** | 文件名,原样落 wire,不得为空 |
| `mode` | string | 否 | 传输模式,缺省 `octet`。原样落 wire **不规范化**;已知性判定大小写不敏感(`OCTET` 与 `octet` 同样合规) |
| `options` | list | oack **是** | RFC 2347 选项,`{name, value}` 对按声明顺序落 wire;oack 须至少一项 |
| `block` | uint16 | data/ack **是** | 块号。**缺省是硬错**(防静默产出 DATA[0]);显式 `block: 0` 合法 —— ACK[0] 用于确认 WRQ / OACK |
| `data` | string | data | 载荷字节,与 `data_hex` 互斥;均空 = 0 字节末块(传输结束信号) |
| `data_hex` | string | data | `0x…` 原始字节,与 `data` 互斥;二进制内容用这个 |
| `code` | 名称 / 数字 | 否 | error 的错误码,缺省 `not_defined`(0)。名称:`not_defined` / `file_not_found` / `access_violation` / `disk_full` / `illegal_operation` / `unknown_tid` / `file_exists` / `no_such_user` / `option_negotiation`(RFC 2347 补 8);数字直接透传 |
| `message` | string | 否 | error 的人读文案,NUL 终止 |

与 opcode 无关的字段**不报错**,序列化时忽略并产 `tftp.field-ignored` 告警(见下)。

## 组合规则

- `opcode` 是唯一必填字段,其余按 opcode 收窄:rrq/wrq 要 `filename`,data/ack 要
  `block`,oack 要非空 `options`。
- `data` 与 `data_hex` 互斥;均空合法(0 字节末块)。`@file(path)` 注入走 `data`
  (hex 字段注入原始字节会破坏语义,见 `_conventions`)。
- mode / filename **原样落 wire**:折叠、截断、规范化一概不做。判定(告警)与编码
  (wire)是两条独立通道,`MAIL` 落 wire 仍是 `MAIL`。
- `tftp` 可进 UDP flow 的 `messages`,也可在 `packets` 里单包手写(错误报文常用)。
- 块号上限 65535(uint16);单个 DATA 手写超 512 字节不拦,产
  `tftp.data-oversize` 告警。批量内容请用 `tftp_transfer` 宏,不要手写几百条 DATA。

## 静默陷阱

- **端口切换(TID)**:RRQ/WRQ 发往 69,服务器随即从**新 TID** 发数据 —— 客户端后续
  只认新 TID。一条 flow 的端口是固定声明值,表达不了切换:按 FTP 先例拆成
  「请求 flow(仅 RRQ/WRQ)+ 数据 flow(新 TID)」两条 flow,`start_after` 锚到
  请求消息。完整示例见 `pmaker://examples`(tftp/read_simple)。
- **选项顺序即 wire 顺序**:`options` 是列表不是 map,声明顺序原样落 wire
  (与 RFC 2347 的协商顺序语义一致)。
- **数字 opcode 只落 2 字节头**:未知 opcode(如 7)之外的字段全部忽略,不报错
  (产 `tftp.field-ignored`);要构造「未知 opcode + 自定义载荷」的畸形,用
  `payload_hex` 手拼整条报文。
- **mode 空缺 = octet,不是不落**:`rrq` 不写 mode 时 wire 上仍有 `octet\0`,
  构造「缺 mode 字段」的畸形报文走 `payload_hex`。

## 一致性告警(软告警,非硬错)

| code | 触发 | 说明 |
|------|------|------|
| `tftp.rq-port` | RRQ/WRQ 所在 flow 的 UDP `dport` 不是 69 | RFC 1350 规定请求发往服务器 69 端口;flow 中 `from: dst` 的请求不检查(端点已交换)。故意构造可忽略 |
| `tftp.mode-obsolete` | mode 折叠后 = `mail`(含 `MAIL` 等变体) | RFC 1350 Appendix II 的废弃模式,后续修订已删除;畸形用例可故意构造,正常场景用 octet/netascii |
| `tftp.mode-unknown` | mode 折叠后不在 {octet, netascii, mail} 里(如 `binary`) | 照常出包,接收端多半解释失败;大小写变体(`OCTET`)不告警 —— RFC 1350 §1 明文允许 |
| `tftp.data-oversize` | DATA 载荷 > 512 字节 | 接收端靠「末块长度 < blksize」判断结束,超长块让结束判定失灵;协商了 blksize 选项时以协商值为准(本检查不跨包追踪协商,恒按 512 基准提示) |
| `tftp.field-ignored` | 写了与 opcode 无关的字段(如 ack 里写 `data`) | 该字段序列化时被静默忽略,告警提前提示可省调试;故意构造可忽略 |

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:02", dst: "00:11:22:33:44:01" }
      - ipv4: { src: "10.0.0.2", dst: "10.0.0.1", ttl: 64 }
      - udp:  { sport: 54321, dport: 50000 }
      - tftp: { opcode: ack, block: 1, data: "ignored" }
```

上例过校验、照常出包,产一条 `tftp.field-ignored` 告警(ack 只认 `block`,
`data` 被忽略);要真发「带载荷的 ACK」畸形字节用 `payload_hex` 手拼。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 未知 / 私有 opcode(0/7/255) | `opcode: 7`(数字透传,只落 2 字节头) |
| DATA[0] / 错误块号 | `block: 0` 或任意值(显式写即合法) |
| 超长 DATA(> blksize) | `data` 直接写长内容,吃一条 `tftp.data-oversize` 告警 |
| 空 OACK / 缺 mode 的 RRQ / 未知 opcode + 载荷 | 结构化通道表达不了,整条报文 `payload_hex` 手拼 |
| 错误校验和 | `udp.checksum` 覆盖(两态语义) |
| 块号跳变 / 丢 ACK / 重复块 | 手写多条 `tftp` 报文(或 flow messages),宏不产畸形 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `opcode 必填` | 每个层都要写 `opcode`;可拆多层的场景(如 DATA + ACK)写成多条报文 |
| `未知 opcode` | 名字拼错了;可用 rrq/wrq/data/ack/error/oack 或数字 |
| `需要 filename` | rrq/wrq 的 `filename` 必填且不得为空 |
| `需要 block` | data/ack 的 `block` 必填(缺省会静默产出 DATA[0]);`block: 0` 也要显式写 |
| `data 和 data_hex 只能配置一个` | 文本内容用 `data`,二进制用 `data_hex`,二选一 |
| `未知 code` | error 的 `code` 名字拼错了;可用 RFC 1350/2347 名单里的名字或数字 |
| `options 至少一个` | 空 OACK 几乎必是配置错误;构造空 OACK 畸形包请用 `payload_hex` |
| `options[0] 需要 name` | 选项对缺 `name`;每个选项 name/value 都必填 |
| `options[0] 需要 value` | 选项对缺 `value`;空值也是非法 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: {}
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: fetch, filename: "a.txt" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: rrq, mode: octet }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: data, data: "hello" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: data, block: 1, data: "a", data_hex: "0x01" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: error, code: no_such_code, message: "boom" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp: { opcode: oack, options: [] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp:
          opcode: rrq
          filename: "a.txt"
          options:
            - { value: "1024" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 69 }
      - tftp:
          opcode: rrq
          filename: "a.txt"
          options:
            - { name: blksize }
```

## 相关

`pmaker://schema/tftp_transfer`(文件传输宏)、`pmaker://schema/udp_session`
(UDP 会话与端口切换模式)、`pmaker://schema/udp`、`pmaker://schema/overview`
