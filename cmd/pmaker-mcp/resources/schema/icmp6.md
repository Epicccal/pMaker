# icmp6 —— `icmpv6` 的别名

`icmp6` 与 `icmpv6` 是**同一个层**的两个合法写法:字段、校验、序列化行为完全一致
(解码时映射到同一个 `ICMPv6Fields`)。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv6:  { src: "2001:db8::1", dst: "2001:db8::2", hop_limit: 64 }
      - icmp6: { type: echo_request, code: 0, id: 0x0001, seq: 1, payload: "hello" }
```

## 字段

**完整字段速查见 `pmaker://schema/icmpv6`**,本文不重复(避免两处漂移)。

## 静默陷阱

- 两个名字**都能用在 `ipv4.protocol` / `ipv6.next_header` 的覆盖值里**
  (`protocol: icmp6` 与 `protocol: icmpv6` 都推出 58),但在 `stack` 里请只挑一个写法,
  混用会让摘要输出里出现两种层名、增加比对噪音。
- 新场景建议写 `icmpv6`(与 `ipv6` 命名一致);`icmp6` 保留是为兼容既有场景文件。

## 相关

`pmaker://schema/icmpv6`
