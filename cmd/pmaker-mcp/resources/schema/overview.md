# pMaker 场景 YAML 概览

pMaker 用声明式 YAML 描述协议栈与会话,离线生成确定性的 `.pcap` 文件。本文是入口导读;
各层(eth/ipv4/tcp/dns/…)的完整字段见 `pmaker://schema/<层名>`(如 `pmaker://schema/tcp`)。

## 顶层结构

```yaml
link_type: ethernet          # ethernet(默认)| raw | ipv4 | ipv6
seed: 42                     # 随机种子,保证同输入逐字节相同
base_time: 2024-01-01T00:00:00Z  # 可选,唯一绝对时间锚(ISO8601/UTC),缺省=确定性 2020 基准
packets:                     # 逐包(无状态),与 flows 二选一或共存
  - stack: [ ... ]
flows:                       # 有状态会话(TCP 握手/挥手/seq-ack 自动推导)
  - name: ...
    stack: [ ... ]
    messages: [ ... ]
```

## packet(逐包,无状态)

每个 packet 是一个从外到内的有序 `stack`(层列表),元素是单键 map,允许同类型重复(QinQ 双层 vlan)与递归嵌套(GRE 内层再套整包)。

```yaml
packets:
  - name: syn                # 可选,供 quote_from 引用
    offset_time: +1s         # 可选,相对上一包(第一包相对 base_time)
    stack:
      - eth:    { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:   { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:    { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

## flow(有状态会话)

`flows` 展开成握手 + 消息 + 挥手的完整包序列,自动维护 seq/ack、MSS 分段。`stack` 中的 `src` = TCP SYN 发起方,`dst` = 接收方。

```yaml
flows:
  - name: http-get
    offset_time: +0s          # 可选,流锚 = base_time + offset;缺省=base(跨流并发)
    start_after: "other-flow" # 可选,"flow名" 或 "flow名.message_id",跨流依赖
    stack:
      - eth:          { src: "...", dst: "..." }
      - ipv4:         { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:          { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session:  { open: handshake, close: fin }   # open: handshake|none; close: fin|rst|none
    messages:
      - from: src              # src | dst
        message_id: req1       # 可选,供其它 flow 的 start_after 引用
        offset_time: +100ms    # 可选,相对上一条消息末尾
        segment: { mss: 8, interval: "+10ms" }  # 可选,切段 + 段间隔
        stack:
          - http_request: { method: GET, url: /index.html, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response: { status: 200, body: "hi" }
```

**约束**:flow.stack 须含 `eth` + `tcp` + 恰好一个网络层(`ipv4` 或 `ipv6`);每条 message 当前仅一个 payload 生产层。

## 时间字段

- `base_time`:唯一绝对锚(ISO8601/UTC,如 `2024-01-01T00:00:00Z`),缺省=确定性 2020 基准。
- `packet.offset_time`:相对**上一包**(第一包相对 base);缺省接续 +1ms。
- `flow.offset_time`:流锚相对 base_time;缺省=base(跨流并发)。
- `message.offset_time`:相对**上一条消息末尾**(第一条相对握手完成);缺省紧接。
- `segment.interval`:同消息各数据段间隔,缺省 1ms。
- 所有 offset 为**非负时长**(如 `+1.5s`/`500ms`/`0s`),负值解析即失败。
- `start_after`(flow 级 / message 级):`"flow名"`(整流结束)或 `"flow名.message_id"`;禁止同流自引,循环依赖被拦截。

## 层类型清单

| 类别 | 层名 | schema |
|------|------|--------|
| L2 | `eth`、`vlan` | `pmaker://schema/eth`、`pmaker://schema/vlan` |
| L3 | `ipv4`、`ipv6`、`gre` | `pmaker://schema/ipv4`、`pmaker://schema/ipv6`、`pmaker://schema/gre` |
| L4 | `tcp`、`udp`、`tcp_session`(仅 flow) | `pmaker://schema/tcp`、`pmaker://schema/udp` |
| 控制/应用 | `icmp`、`icmpv6`、`dns`、`http_request`、`http_response`、`ftp_request`、`ftp_response`、`telnet`、`smtp_request`、`smtp_response` | 对应 `pmaker://schema/<层名>` |
| 兜底 | `payload`、`payload_hex` | `pmaker://schema/payload` |

## 通用约定

- **next-proto / EtherType 自动串接**:按层栈自动推导,可逐层显式覆盖(`type`/`tpid`/`ethertype`)制造解析断链。
- **checksum**:TCP/UDP 伪首部自动绑定就近 IP 层(多层 IP 绑内层);可显式覆盖制造错误 checksum。
- **`@file(<path>)`**:任意 string 字段可写文件占位符,解析时(`Parse`)替换为文件原始字节(支持二进制)。CLI 的 `Load` 即「读文件 → `Parse`」,相对路径相对 scenario 文件所在目录;MCP server 直接 `Parse`,相对路径相对 `workdir`。`@@` 转义为字面 `@`。
- **`Hex` 字段**(ethertype/tpid/type/checksum):接受十进制或 `0x88a8` 形式。
- **确定性**:同 scenario + seed → 逐字节相同 pcap;全程不用 `time.Now()`。
