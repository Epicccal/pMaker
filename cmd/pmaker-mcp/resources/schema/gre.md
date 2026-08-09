# gre —— GRE 隧道封装(L3)

封装层,内层套完整报文(可递归)。无字段(next-proto 自动推导)。

```yaml
- ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }   # 外层,protocol 自动 = GRE(47)
- gre:  {}                                     # protocol 自动 = 内层 ethertype
- ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }  # 内层 IP
- tcp:  { sport: 1234, dport: 443, flags: [SYN] }
```

## next-proto 串接

`gre.Protocol` = 内层 EtherType:内层 `ipv4` → `0x0800`;内层 Ethernet(TEB)→ `0x6558`。
GRE 外层 IP 的 protocol 自动 = 47。
