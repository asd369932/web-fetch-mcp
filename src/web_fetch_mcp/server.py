"""web-fetch-mcp — 抓取网页并转成 AI 可读文本的 MCP Server。

工具:
- fetch:     抓 URL → 去 script/style/标签 → 返回纯文本(带大小与超时边界)
- fetch_json: 抓 JSON API 并格式化返回
- extract_links: 提取页面里所有链接(用于顺着页面爬)

安全边界(SSRF 防护,抓取类工具的必修课):
- scheme 只允许 http/https
- host 解析出的每个 IP 都检查:环回/私网/链路本地/云元数据地址一律拒绝
- 响应大小上限 2MB、连接与读取超时
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="web-fetch-mcp",
    title="Web Fetch",
    version="0.1.0",
    instructions=(
        "Fetch web pages and JSON APIs as clean text. Private/loopback/link-local "
        "addresses are blocked (SSRF guard). Prefer fetch_json for APIs. "
        "HTML is stripped of script/style before returning."
    ),
)

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 20
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0"

# 云元数据地址(SSRF 高危目标),即使在某些网络里不算"私网"也要拦
_BLOCKED_HOSTS = {
    "169.254.169.254",        # AWS/GCP/Azure 元数据
    "metadata.google.internal",
    "100.100.100.200",        # 阿里云元数据
}


class FetchError(Exception):
    pass


def _check_host(host: str) -> None:
    """解析 host 的全部 IP,任何一个落到禁区即拒绝。"""
    if host.lower() in _BLOCKED_HOSTS:
        raise FetchError(f"目标地址被禁止(云元数据): {host}")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise FetchError(f"域名解析失败: {host} ({e})") from e

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str.split("%")[0])
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise FetchError(f"目标解析到受限地址({ip_str}),拒绝访问")


def _validate_url(url: str) -> str:
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"只允许 http/https,收到: {parsed.scheme or '(无)'}")
    if not parsed.hostname:
        raise FetchError("URL 缺少主机名")
    _check_host(parsed.hostname)
    return url


class _TextExtractor(HTMLParser):
    """去 script/style,把标签转成空白,保留可读文本。"""

    _SKIP = {"script", "style", "noscript", "svg", "head", "template"}
    _BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
              "section", "article", "header", "footer", "blockquote"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()
        if self._skip_depth == 0:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


def _http_get(url: str) -> tuple[bytes, str, str]:
    """返回 (body, content_type, final_url)。大小与超时都有硬边界。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError(f"响应超过 {MAX_BYTES} 字节上限,已中止")
            return body, ctype, resp.geturl()
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise FetchError(f"连接失败: {e.reason}") from e
    except (TimeoutError, socket.timeout) as e:
        raise FetchError(f"超时({TIMEOUT}s)") from e


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

@server.tool(description="抓取网页并返回纯文本(去脚本/样式/标签)。上限 2MB、20 秒超时。")
def fetch(url: str, max_chars: int = 20000) -> str:
    """抓 HTML 页面。max_chars 控制返回给模型的最大字符数。"""
    try:
        u = _validate_url(url)
        body, ctype, final = _http_get(u)
    except FetchError as e:
        return f"[拒绝/失败] {e}"

    charset = "utf-8"
    m = re.search(r"charset=([\w-]+)", ctype, re.IGNORECASE)
    if m:
        charset = m.group(1)
    text = body.decode(charset, errors="replace")

    if "html" in ctype.lower() or text.lstrip()[:1] == "<":
        parser = _TextExtractor()
        try:
            parser.feed(text)
        except Exception:
            pass  # HTMLParser 对畸形页面足够宽容,真挂了就退回全文
        out = parser.text()
        title = parser.title
    else:
        out, title = text, ""

    cap = max(100, min(int(max_chars), 100_000))
    truncated = len(out) > cap
    if truncated:
        out = out[:cap] + f"\n…<截断,全文 {len(out)} 字符>"

    header = f"# {final} ({len(body)} 字节, Content-Type: {ctype})"
    if title:
        header += f"\n# 标题: {title}"
    return header + "\n\n" + out


@server.tool(description="抓取 JSON API 并返回格式化结果(同样受 SSRF 防护与大小限制)。")
def fetch_json(url: str, max_chars: int = 20000) -> str:
    """抓 JSON 接口。非 JSON 响应会原样返回前 500 字符。"""
    try:
        u = _validate_url(url)
        body, ctype, final = _http_get(u)
    except FetchError as e:
        return f"[拒绝/失败] {e}"

    text = body.decode("utf-8", errors="replace")
    try:
        data: Any = json.loads(text)
        pretty = json.dumps(data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        preview = text[:500]
        return (f"[非 JSON] Content-Type: {ctype}\n"
                f"原文前 500 字符:\n{preview}")

    cap = max(100, min(int(max_chars), 100_000))
    truncated = len(pretty) > cap
    if truncated:
        pretty = pretty[:cap] + f"\n…<截断,全文 {len(pretty)} 字符>"
    return f"# {final}\n\n{pretty}"


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        d = dict(attrs)
        href = d.get("href")
        if href:
            self._current = {"href": href, "text": ""}

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["text"] += data.strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current is not None:
            self._current["text"] = re.sub(r"\s+", " ", self._current["text"]).strip()[:120]
            self.links.append(self._current)
            self._current = None


@server.tool(description="提取页面上所有链接(绝对化后返回,可跟去下一层)。")
def extract_links(url: str, max_links: int = 100) -> str:
    """抓页面并提取 <a href>。相对链接会换算成绝对地址。"""
    try:
        u = _validate_url(url)
        body, ctype, final = _http_get(u)
    except FetchError as e:
        return f"[拒绝/失败] {e}"

    text = body.decode("utf-8", errors="replace")
    collector = _LinkCollector()
    try:
        collector.feed(text)
    except Exception:
        pass

    seen: set[str] = set()
    links: list[dict[str, str]] = []
    for l in collector.links:
        absolute = urllib.parse.urljoin(final, l["href"])
        if absolute in seen or not absolute.startswith(("http://", "https://")):
            continue
        seen.add(absolute)
        links.append({"url": absolute, "text": l["text"]})
        if len(links) >= max(1, min(int(max_links), 500)):
            break

    return json.dumps({"page": final, "count": len(links), "links": links},
                      ensure_ascii=False, indent=2)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
