# udp_session —— UDP 会话标记(仅 flow.stack)

不是真实协议层,而是告诉 flow 展开器「**本 flow 是 UDP 会话**」。UDP 无连接,
没有握手 / 挥手 / seq/ack / 对端 ACK 可补;本层的唯一职责是把 `messages` 的方向语义
(`from: src` / `from: dst`)翻译成端点正反转换(反向数据报交换 eth / ip 的 src/dst 与
会话 UDP 层的 sport/dport)。**只能出现在 `flows[].stack` 里**,standalone `packets`
写它会被拒。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: echo
    stack:
      - eth:          { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:         { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - udp:          { sport: 49152, dport: 53 }
      - udp_session:  {}
    messages:
      - from: src
        stack:
          - payload: { payload: "query" }
      - from: dst
        stack:
          - payload: { payload: "answer" }
```

## 字段

零字段。`- udp_session: {}` 与 `- udp_session:`(null)等价,统一推荐 `{}`。
写任何字段(如 `udp_session: {timeout: 3}`)会被未知字段校验硬拒 —— 不是静默忽略。

## 组合规则(硬错)

- **必须显式写**,不像 `tcp_session` 可省略:`flow.stack` 含 `udp` 而不写 `udp_session`
  会报错(见下表「含 udp 无 tcp」)。省略的宽容只留给 TCP(历史兼容,缺省 handshake/fin),
  UDP 会话必须声明,报错才能点名层。
- `flow.stack` **必须**同时含 `eth`、恰好一个网络层(`ipv4` 或 `ipv6`)、`udp`、`udp_session`;
  可选夹多层 `vlan`。会话层与传输层须匹配:`tcp_session` 配 `udp`、`udp_session` 配 `tcp`
  都会被拒;两者并存也被拒(二选一)。
- 每条 message 恰好展开**一个** UDP 数据报;`from: dst` 的消息交换端点后从对端发出。
- **`segment` 不支持**(UDP 无流重组,按 mss 切出的每个数据报都单独无法解析):
  确需多个数据报请拆成多条 `message` 并用 `offset_time`。
- `message.stack` 允许任何 payload 生产层(与 TCP 会话同一套白名单):`payload` /
  `payload_hex` / `dns` 是数据报常用层;放 TCP 流式协议层(`http_request` / `smtp_*` 等,
  完整清单见下「一致性告警」)会产软告警 `udp.stream-app-layer`(流式层无帧边界语义),
  确属故意的畸形用例可忽略。清单之外的层(含后续新增的数据报层)默认不告警。
- UDP flow 的 `messages` 不能为空(空 flow 一个包也不产)。

## 时间模型

无握手、无对端 ACK、无挥手:

- 首条消息直接以流锚(`base_time` + `flow.offset_time`,或 `start_after` 被引时刻)为参照,
  不像 TCP 要等握手完成;
- 相邻消息间隔 = `message.offset_time`(缺省紧接上一条,即 +1ms);
- 每条消息末尾 +1ms 是下一条消息的接续点;流结束时刻 = 末条消息 + 1ms
  (跨流 `start_after` 引用裸 flow 名时对齐到这里)。

## 静默陷阱

- **`sport`/`dport` 是声明值,反向只交换不推导**:不像 TCP 的 seq/ack 逐包推导,
  UDP 端口从声明原样落 wire(反向消息交换 sport/dport)。
- **VXLAN 双 UDP 栈**:outer(隧道)UDP 端口与 VNI 两向不变,只有 inner(会话)UDP
  端口随方向交换 —— 展开器按「会话层前一层」定位会话传输层,不会误动 outer。
- 端口切换(TFTP TID 式)不支持在一条 flow 里表达:按 FTP 先例拆成两条 flow +
  `start_after`。

## 一致性告警(软告警,非硬错)

| code | 触发 | 说明 |
|------|------|------|
| `udp.stream-app-layer` | UDP 会话的 `message.stack` 含 TCP 流式协议层 | 判定按流式层清单**正向**匹配:`http_request` / `http_response` / `ftp_request` / `ftp_response` / `telnet` / `smtp_request` / `smtp_response` / `pop3_request` / `pop3_response` / `imap_request` / `imap_response` / `eml_data`。流式层的语义是「字节流的一段」,放进单个数据报无帧边界语义,解析端无法还原消息;照常出包。清单之外(`payload` / `payload_hex` / `dns` 及后续新增的数据报层)默认不告警 —— 新数据报协议无需任何登记;DNS 本就是「一条消息一个数据报」(RFC 1035 §4.2.1)。确属故意的畸形用例可忽略 |

```yaml
link_type: ethernet
flows:
  - name: stream-in-datagram
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:         { sport: 49152, dport: 53 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /a }
```

上例过校验、照常出包,产一条 `udp.stream-app-layer` 告警(把 HTTP 字节放进
UDP 数据报,解析端无法还原);要落非标字节用 `payload` / `payload_hex`。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 单向无应答(只问不答) | `messages` 只写 `from: src` |
| 错误校验和 | `flow.stack` 的 `udp.checksum` 写值(每包同值,有软告警可忽略) |
| IPv6 下 checksum 0(非法值) | `udp.checksum: 0x0` + `ipv6`(RFC 8200 §8.1 要求必校验,工具照写并告警) |
| UDP 端口不匹配的应答 | `message.stack` 用 `payload_hex` 手拼,或走 `packets` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `含 udp 无 tcp:UDP 会话需显式声明 udp_session` | `flow.stack` 末位补 `- udp_session: {}`。UDP 会话与 TCP 不同,不可省略 |
| `会话层与传输层不匹配` | `tcp_session` 需配 `tcp`、`udp_session` 需配 `udp`,二选一且须紧邻 |
| `只能用于 flow.stack,不能出现在 standalone packet 的 stack 里` | 普通数据报直接在 `packets` 里写 `udp` + payload,无需会话标记 |
| `只能在 vxlan 之后的 inner 段` | 会话跑在隧道内层:`udp_session` 移到隧道层之后的 inner 段末位(gre 切点同理,报错为「只能在 gre 之后的 inner 段」) |
| `UDP 无流重组,不支持 segment 切段` | 拆成多条 `message` 并用 `offset_time` 控制间隔 |
| `UDP flow 的 messages 不能为空` | 要产包就加消息;要空会话请去掉整条 flow |
| `不支持字段 "timeout"` | 零字段层:任何字段都硬拒,UDP 会话没有可配参数 |
| `会话层(tcp_session 或 udp_session)不可同时出现` | 会话层二选一;UDP 会话写 `udp_session`,TCP 会话写 `tcp_session` |

```yaml-bad
link_type: ethernet
flows:
  - name: no-session
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:  { sport: 49152, dport: 53 }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: mismatch
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:         { sport: 49152, dport: 80 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: bad-segment
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:         { sport: 49152, dport: 53 }
      - udp_session: {}
    messages:
      - from: src
        segment: { mss: 4 }
        stack:
          - payload: { payload: "abcdef" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:          { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:         { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:          { sport: 49152, dport: 53 }
      - udp_session:  {}
```

```yaml-bad
link_type: ethernet
flows:
  - name: unknown-field
    stack:
      - eth:          { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:         { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:          { sport: 49152, dport: 53 }
      - udp_session:  { timeout: 3 }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: empty-messages
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:         { sport: 49152, dport: 53 }
      - udp_session: {}
```

```yaml-bad
link_type: ethernet
flows:
  - name: outer-session
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:         { sport: 51000, dport: 4789 }
      - udp_session: {}
      - vxlan:       { vni: 100 }
      - eth:         { src: "aa:bb:cc:dd:ee:01", dst: "aa:bb:cc:dd:ee:02" }
      - ipv4:        { src: "192.168.1.1", dst: "192.168.1.2" }
      - udp:         { sport: 5300, dport: 53 }
      - udp_session: {}
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: both-sessions
    stack:
      - eth:          { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:         { src: "10.0.0.10", dst: "10.0.0.80" }
      - udp:          { sport: 49152, dport: 53 }
      - tcp_session:  {}
      - udp_session:  {}
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

## 相关

`pmaker://schema/udp`、`pmaker://schema/tcp_session`、`pmaker://schema/_why_udp_session`、
`pmaker://schema/overview`(flow / messages / 时间编排)
