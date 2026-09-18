# dns —— DNS 报文(L7,通常走 udp)

一个 `dns` 层 = 一条完整 DNS 消息(报头 + questions/answers/authorities/additionals)。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.53", ttl: 64 }
      - udp:  { sport: 40000, dport: 53 }
      - dns:
          id: 0x1234
          qr: query
          recursion_desired: true
          questions:
            - { name: "example.com", type: A, class: IN }

  - stack:
      - eth:  { src: "66:77:88:99:aa:bb", dst: "00:11:22:33:44:55" }
      - ipv4: { src: "10.0.0.53", dst: "10.0.0.1", ttl: 64 }
      - udp:  { sport: 53, dport: 40000 }
      - dns:
          id: 0x1234
          qr: response
          rcode: no_error
          recursion_available: true
          questions:
            - { name: "example.com", type: A }
          answers:
            - { name: "example.com", type: A, class: IN, ttl: 300, data: "93.184.216.34" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | uint16 | 否 | 事务 ID,缺省 0 |
| `qr` | string | 否 | `query`(缺省)/ `response`;其它值**报错** |
| `opcode` | string | 否 | `query`(缺省)/ `iquery` / `status`;**无数字写法** |
| `rcode` | string | 否 | `no_error`(缺省)/ `format_error` / `server_failure` / `name_error` / `not_implemented` / `refused`;**无数字写法** |
| `authoritative` | bool | 否 | AA |
| `truncated` | bool | 否 | TC |
| `recursion_desired` | bool | 否 | RD |
| `recursion_available` | bool | 否 | RA |
| `authenticated_data` | bool | 否 | AD(RFC 4035,编入 Z 的 bit5) |
| `checking_disabled` | bool | 否 | CD(RFC 4035,编入 Z 的 bit4) |
| `questions` | list | 否 | 查询段 |
| `answers` / `authorities` / `additionals` | list | 否 | 三个资源记录段,结构相同 |

四个段**至少一个非空**(全空报错)。段计数(QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT)恒由实际记录数推导。

### question 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 域名,尾点可写可不写(会被剥掉) |
| `type` | 名称 / 数字 | 否 | 缺省 `A` |
| `class` | 名称 | 否 | 缺省 `IN`;只认 `IN`/`CS`/`CH`/`HS` |

### 资源记录(answers / authorities / additionals)字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 域名 |
| `type` | 名称 / 数字 | 否 | 缺省 `A` |
| `class` | 名称 | 否 | 缺省 `IN` |
| `ttl` | uint32 | 否 | 秒,缺省 0 |
| `data` | 按 type 而定 | 与 `payload_hex` **二选一** | 结构化 RDATA |
| `payload_hex` | string | 与 `data` **二选一** | `0x…` 原始 RDATA 字节 |

**`data` 的形状按 `type` 决定**:

| type | `data` 写法 |
|------|-------------|
| `A` | IPv4 字符串 `"93.184.216.34"` |
| `AAAA` | IPv6 字符串 `"2606:2800:220:1::248"` |
| `CNAME` / `NS` / `PTR` | 域名字符串 |
| `MX` | `{ preference: 10, exchange: "mail.example.com" }` |
| `TXT` | 字符串或字符串列表(每串 ≤255 字节) |
| `SOA` | `{ mname, rname, serial, refresh, retry, expire, minimum }` |
| `SRV` | `{ priority, weight, port, target }` |
| 其它(数字 type) | **不能用 `data`**,必须写 `payload_hex` |

## 组合规则

- 四个段全空 → 硬错。每条 question / RR 必须有 `name`。
- RR 的 `data` 与 `payload_hex` 互斥,且必须有其一。
- `type` 接受**已知名字或任意数字**(`"99"` / `"0x0063"`);`class` / `opcode` / `rcode` / `qr`
  **只认名字**,写数字或拼错都会在出包阶段报错(如 `未知 class "1"(支持 IN/CS/CH/HS)`)。
- 数字 `type` 的 RR 必须配 `payload_hex`,否则出包阶段报 `暂不支持 DNS RR 类型 "99"`
  ——工具无从知道该 type 的 RDATA 结构。question 段的数字 `type` 无此限制(question 无 RDATA)。
- 域名长度在出包阶段校验:单标签 ≤63、编码后整名 ≤255,空标签(`a..b`)报错。
- **`dns` 可进 UDP flow 的 `messages`**(`message.stack` 允许 `dns`,单层序列化为 DNS 消息字节,
  问答两个方向用 `from: src` / `from: dst`,见 `pmaker://schema/udp_session`);
  **TCP flow 的 `message.stack` 不收 `dns`**(缺 2 字节长度前缀,见下)—— DNS-over-TCP
  的会话时序请用 `packets` + `offset_time`,或整段走 `payload_hex`。

## 静默陷阱

- **DNS-over-TCP 缺 2 字节长度前缀**:把 `dns` 放在 `tcp` 之下,工具直接落 DNS 消息字节,
  **不会**按 RFC 1035 §4.2.2 加两字节长度前缀,解析端会认不出。需要合规的 TCP 形态时,
  自己用 `payload_hex` 拼前缀 + 消息字节。
- **只要任意一条 RR 带 `payload_hex`,整条消息切换到手写编码器**(gopacket 没有原始 RDATA 通道)。
  同一份配置下两条路径语义已对齐,但这是"整条消息"级的切换,不是"这一条 RR"级的。
- **名字不做压缩指针**:所有域名逐标签展开。真实抓包普遍用 0xC0 压缩,字节级比对会不一致
  (解析仍正确)。要构造压缩指针只能 `payload_hex`。
- **段计数撒不了谎**:QDCOUNT 等恒等于实际记录数,构造不出"声明 5 条实际 1 条"的畸形;
  这类用例整段走 `payload_hex`。
- `CNAME` / `NS` / `PTR` 的 `data` 写空串**不报错**,会静默产出根域 —— 而且 gopacket 对根名 RR 的
  RDLENGTH 会多算 1 字节(实测 `00 02 00 00`),是条无声的畸形。`MX.exchange` / `SRV.target`
  写空则是报错的(同样原因,根 target 请用 `payload_hex`)。
- 名字的尾点被无条件剥掉,`"example.com."` 与 `"example.com"` 产出完全相同的字节。
- **无 EDNS0 / OPT 结构化支持**:OPT(41)只能靠数字 `type` + `payload_hex` 手拼。
- Z 的保留位(bit6)恒为 0,`authenticated_data` / `checking_disabled` 只能动 bit5/bit4。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 未知 / 私有 RR 类型 | `type: "99"`(或 `"0x0063"`)+ `payload_hex: "0x…"` |
| 撒谎的 RDLENGTH、压缩指针、段计数错配 | 无字段,整层走 `payload_hex` |
| 超长 / 非法域名 | 域名长度在出包阶段拦截,越界名字走 `payload_hex` |
| 缺 2 字节长度前缀之外的 TCP 形态畸形 | `payload_hex` 自拼 |
| 响应里塞不匹配的 question(缓存投毒素材) | `qr: response` + 与 answers 不同的 `questions[].name` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要至少一个 question 或资源记录` | 空 `dns: {}` 不合法;至少给一个 `questions` 或一条 RR。要构造完全空的 DNS 消息走 `payload_hex` |
| `questions[0] 需要 name` | question 的 `name` 必填。根域查询也要显式写(写 `"."`) |
| `answers[0] 需要 name` | RR 的 `name` 必填,三个 RR 段同理 |
| `payload_hex 与 data 只能配置一个` | 结构化 RDATA 与原始 RDATA 二选一。想在结构化内容后追加字节,把整段 RDATA 拼成 `payload_hex` |
| `需要 data 或 payload_hex` | RR 必须给 RDATA。未知 type 用 `payload_hex`,已知 type 用 `data` |
| `DNS over TCP 暂不支持` | TCP flow 的 `message.stack` 不收 `dns`(缺 2 字节长度前缀);需前缀可用 `payload_hex` 手拼,或 UDP flow 里用 `dns` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 53 }
      - dns:  {}
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 40000, dport: 53 }
      - dns:
          questions:
            - { type: A }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 53, dport: 40000 }
      - dns:
          qr: response
          answers:
            - { type: A, ttl: 300, data: "1.2.3.4" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 53, dport: 40000 }
      - dns:
          qr: response
          answers:
            - name: "example.com"
              type: A
              data: "1.2.3.4"
              payload_hex: "0xdeadbeef"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 53, dport: 40000 }
      - dns:
          qr: response
          answers:
            - { name: "example.com", type: A, ttl: 300 }
```

```yaml-bad
link_type: ethernet
flows:
  - name: dns-over-tcp
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.53" }
      - tcp:         { sport: 49152, dport: 53 }
      - tcp_session: {}
    messages:
      - from: src
        stack:
          - dns: { id: 0x1234, qr: query, questions: [{ name: "example.com", type: A }] }
```

## 相关

`pmaker://schema/udp`、`pmaker://schema/udp_session`、`pmaker://schema/tcp`、
`pmaker://schema/payload_hex`、`pmaker://schema/overview`
