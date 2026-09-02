# icmp6 —— `icmpv6` 的别名

`icmp6` 与 `icmpv6` 是同一个层的两个合法写法,字段与行为完全一致。

```yaml
- icmp6: { type: 128, code: 0 }    # 等价于 - icmpv6: { type: 128, code: 0 }
```

**完整字段速查见 `pmaker://schema/icmpv6`**(本文不重复,避免两处漂移)。

新场景建议写 `icmpv6`(与 `ipv6` 的命名一致);`icmp6` 保留是为兼容既有场景文件。
