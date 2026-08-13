# http_request —— HTTP 请求(L7,走 tcp)

```yaml
- http_request:
    method: GET
    url: /index.html
    version: HTTP/1.1
    headers:
      Host: example.com
      User-Agent: pMaker/0.1
      Accept: "*/*"
    body: ""
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | string | 否 | 缺省 GET |
| `url` | string | 否 | 请求路径 |
| `version` | string | 否 | 缺省 HTTP/1.1 |
| `headers` | map[string]string | 否 | 头部(保留 YAML 声明顺序、支持重复头如多个 `Set-Cookie`) |
| `body` | string | 否 | 请求体;可用 `@file(...)` 注入文件内容 |

> headers 保留 YAML 声明顺序输出(不再按 key 字典序);支持重复头(如多个 `Set-Cookie`)。
