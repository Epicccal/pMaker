# tcp_session —— TCP 会话控制(仅 flow.stack)

不是真实协议层,而是告诉 flow 展开器如何处理握手/挥手。

```yaml
- tcp_session: { open: handshake, close: fin }
```

| 字段 | 值 | 说明 |
|------|------|------|
| `open` | `handshake`(默认)/ `none` | `handshake` 前插 SYN/SYN-ACK/ACK;`none` 假设已建连 |
| `close` | `fin`(默认)/ `rst` / `none` | `fin` 四次挥手;`rst` 对端单包中断;`none` 不收尾 |

**仅出现在 `flows[].stack`**,standalone packet 不用。
