# http_response —— HTTP 响应(L7,走 tcp)

```yaml
- http_response:
    version: HTTP/1.1
    status: 200
    reason: OK
    headers:
      Server: nginx/1.24.0
      Content-Type: text/html; charset=utf-8
      Content-Length: auto        # auto = 由 body 长度自动计算
    body: |
      <html><body>Hello</body></html>
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `version` | string | 否 | 缺省 HTTP/1.1 |
| `status` | int | 否 | 状态码 |
| `reason` | string | 否 | 状态短语 |
| `headers` | map[string]string | 否 | 头部;`Content-Length: auto` 自动按 body 长度计算 |
| `body` | string | 否 | 响应体;可用 `@file(...)` 注入 |

> headers 按 key 字典序输出(未保留原序)。
