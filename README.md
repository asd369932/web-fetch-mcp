# web-fetch-mcp

抓取网页和 JSON API,转成 AI 可直接读的干净文本 —— 带 SSRF 防护、大小上限和超时。

## 为什么做这个

抓取类工具的经典事故是 SSRF(服务端请求伪造):AI 被诱导去抓 `http://169.254.169.254/`(云元数据),把服务器凭据读出来。字符串黑名单挡不住,因为可以绕:

```
169.254.169.254        → 直接写死
0xA9FEA9FE             → 十六进制
http://[::ffff:169.254.169.254]/   → IPv6 映射
internal-host-name     → 解析后指向内网
```

这个服务的做法:**把 host 解析成 IP,对每个 IP 做类别判断**(环回/私网/链路本地/保留/组播/未指定),再加云元数据主机名黑名单。域名指向哪里都不影响判定。

## 安全边界

| 边界 | 说明 |
|------|------|
| scheme | 只允许 http / https |
| SSRF | host 解析全部 IP,任一落到环回/私网/链路本地/保留/组播/未指定即拒绝 |
| 云元数据 | `169.254.169.254`、`metadata.google.internal`、`100.100.100.200` 显式拉黑 |
| 大小 | 响应上限 2 MB,超限中止(不截断后假装成功) |
| 超时 | 20 秒连接+读取超时 |

## 安装

```bash
pip install -e .
```

## 配置

```json
{
  "mcpServers": {
    "web-fetch": { "command": "web-fetch-mcp" }
  }
}
```

无环境变量,也不需要 API key。依赖仅 `mcp`(HTTP 走标准库)。

## 工具

### `fetch(url, max_chars=20000)`
抓 HTML → 去 script/style/svg/head → 标签转空白 → 压缩空行。返回页面标题、字节数、Content-Type 和正文。

### `fetch_json(url, max_chars=20000)`
抓 JSON API 并格式化。非 JSON 响应返回前 500 字符预览(便于调试)。

### `extract_links(url, max_links=100)`
提取所有 `<a href>`,相对链接换算为绝对地址,去重后返回。适合顺着页面爬。

## 实测示例

```python
await session.call_tool("fetch", {"url": "https://example.com"})
# → # https://example.com (1256 字节, Content-Type: text/html)
#   # 标题: Example Domain
#
#   Example Domain
#   This domain is for use in illustrative examples...

await session.call_tool("fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
# → [拒绝/失败] 目标地址被禁止(云元数据): 169.254.169.254

await session.call_tool("fetch", {"url": "http://127.0.0.1:8899/"})
# → [拒绝/失败] 目标解析到受限地址(127.0.0.1),拒绝访问
```

## 测试

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

测试不依赖外网:用本地 HTTP server 验证抓取与 SSRF 拦截逻辑。

## License

MIT
