# pMaker 场景 YAML 概览

pMaker 用声明式 YAML 描述协议栈与会话,**离线**生成确定性 `.pcap`(不发包)。本文是入口导读。

- 通则(三级边界 / 两态覆盖 / `@file` / 兜底 / 成帧 / 换行)→ **`pmaker://schema/_conventions`,先读这份**
- 单层字段速查 → `pmaker://schema/<层名>`(如 `pmaker://schema/tcp`)
- 可直接复制的完整场景 → `pmaker://examples`

## 先看这三条:不报错也不告警的坑

校验器拦不住、也不会告警,但会产出与预期不符的字节。写之前先确认不踩:

1. **单段字节上限**:一条 message / 一个 packet 默认作为**单个 TCP 段**发出。不写
   `segment.mss` 就不切段(`tcp.mss` 只是 SYN 通告值,不代劳)。超过 IP 长度字段上限(65535)时
   长度字段**静默回绕**,包体不截断。body 可能较大——**尤其用 `@file` 注入文件**——必须写
   `segment: { mss: 1460 }`。
2. **换行不归一化**:`http_*.body`、`payload`、`multipart` 各 part body、`eml_data` 的
   `raw`/`raw_hex` 均**原样落字节**。YAML 的 `|` 块标量带入的是裸 `\n`;协议要 CRLF 就写
   `"a\r\nb"`(双引号才解释转义)。仅 `eml_data` 结构化模式(`headers`+`body`)会自动归一化。
3. **显式值即关闭自动计算**:写了 `checksum` / `total_length` 一类字段就按原值上 wire,
   自动计算被关掉——这是构造畸形的正道,但**误写**同样不会有任何提示。

其余静默陷阱按层分布,写某层前读该层文档的「静默陷阱」节。

## 顶层结构

```yaml-sketch
link_type: ethernet              # ethernet(默认)| raw | ipv4 | ipv6
base_time: 2024-01-01T00:00:00Z  # 唯一绝对时间锚(ISO8601/UTC),缺省=确定性 2020 基准
packets:                         # 逐包(无状态),与 flows 二选一或共存
  - stack: [ ... ]
flows:                           # 有状态会话(握手/挥手/seq-ack 自动推导)
  - name: ...
    stack: [ ... ]
    messages: [ ... ]
```

## packets:逐包,无状态

每个 packet 是一个**从外到内**的有序 `stack`,元素为单键 map,允许同类型重复(QinQ 双层 `vlan`)
与递归嵌套(GRE 内层再套整包)。next-proto 自动串接,逐层可覆盖(见 `_conventions`)。

```yaml
link_type: ethernet
packets:
  - name: syn              # 可选,供 icmp 的 quote_from 引用
    offset_time: +1s       # 可选,相对上一包(第一包相对 base_time);缺省 +1ms
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

两态 `checksum` / `length` 覆盖在 `packets` 与 `flows` 中均可用。flow 整栈模板把显式值原样
写入每个展开包;`length` 覆盖会产「每包同值」软告警(`flow.override-static`),`checksum` 覆盖同样告警(真值逐包变;
唯一豁免:VXLAN 外层 UDP 在 IPv4 underlay 下写 0,RFC 7348 免校验)。

## flows:有状态会话

展开成握手 + 消息 + 挥手的完整包序列,自动维护 seq/ack 与分段。
`stack` 里的 `src` = TCP SYN 发起方,`dst` = 接收方;反向消息自动反转所有 eth/IP 端点和
inner TCP 端口。单层 VXLAN flow 中,VNI 与 outer UDP 端口两向保持声明值。

```yaml
link_type: ethernet
flows:
  - name: http-get
    offset_time: +0s          # 可选,流锚 = base_time + offset;缺省=base(跨流并发)
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:         { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src             # src | dst
        message_id: req1      # 可选,供 start_after 引用
        offset_time: +100ms   # 可选,相对上一条消息末尾
        segment: { mss: 1460, interval: "+10ms" }   # 可选,切段大小 + 段间隔
        stack:
          - http_request: { method: GET, url: /index.html, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response: { status: 200, body: "hi" }
```

**硬约束**:普通 `flow.stack` 须含 `eth` + `tcp` + 恰好一个网络层(`ipv4` 或 `ipv6`)+
`tcp_session`,可选多层 `vlan`。VXLAN flow 须为 outer `eth + vlan* + IP + udp + vxlan` 与 inner
`eth + vlan* + IP + tcp + tcp_session` 两段,只支持一层 `vxlan`,outer UDP `dport` 须非零。
每条 message 须 ≥1 个 payload 生产层,同段多层按声明顺序拼接(standalone packet 同此规则)。

**方向化 VLAN VID(仅 `flow.stack`)**:`vlan` 可写 `src_vid`/`dst_vid` 取代 `vid`,让上行
(src→dst)与下行(dst→src)带不同标签;单边缺省 = 该方向整层摘除(上行带下行不带 /
上行双层下行单层)。详见 `pmaker://schema/vlan`。

## 时间

- `base_time`:唯一绝对锚。其余全是**非负**时长偏移(`+1.5s` / `500ms` / `0s`),负值解析即失败。
- `packet.offset_time`:相对**上一包**(第一包相对 base);缺省接续 +1ms。
- `flow.offset_time`:流锚相对 base_time;缺省 = base,即**多条 flow 默认并发**(想顺序就给递增 offset)。
- `message.offset_time`:相对**上一条消息末尾**(第一条相对握手完成);缺省紧接。
- `segment.interval`:同消息各数据段间隔,缺省 1ms。
- `start_after`(flow 级 / message 级):`"flow名"`(整流结束)或 `"flow名.message_id"`(该消息完成)。
  用于跨流依赖(如 FTP 控制通道触发数据通道);禁止同流自引,循环依赖会被拦下。

## 层清单

| 类别 | 层名 |
|------|------|
| L2 | `eth`、`vlan` |
| L3 | `ipv4`、`ipv6`、`gre`、`vxlan`(UDP 承载二层隧道:`udp(4789) → vxlan → eth`;支持 `packets` 与单层 VXLAN TCP flow) |
| L4 | `tcp`、`udp`、`tcp_session`(仅 `flow.stack`) |
| 控制/应用 | `icmp`、`icmpv6`(别名 `icmp6`)、`dns`、`http_request`、`http_response`、`ftp_request`、`ftp_response`、`telnet`、`smtp_request`、`smtp_response`、`pop3_request`、`pop3_response`、`imap_request`、`imap_response`、`eml_data` |
| 兜底 | `payload`、`payload_hex` |

各层 schema 一律 `pmaker://schema/<层名>`。

## 子结构(非层,不能放进 `stack`)

| 子结构 | 嵌在哪 | schema |
|--------|--------|--------|
| `multipart` | `http_request` / `http_response` / `eml_data` 的 `multipart` 字段 | `pmaker://schema/multipart` |
| `eml` | `pop3_response.eml`(RETR/TOP)、`imap_*.literal.eml`(APPEND/FETCH);SMTP DATA 用独立的 `eml_data` **层**。四处共用同一份字段,成帧按所在协议自动追加 | `pmaker://schema/eml_data` |
| `literal` | `imap_request` / `imap_response` 的 `literal` 字段(`{n}\r\n` + 八位组) | `pmaker://schema/imap_request` |
