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

import http.client

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


def _check_host(host: str) -> list[str]:
    """解析 host 的全部 IP,逐个做类别检查,返回检查通过的 IP 列表。

    返回值是关键:连接层拿它 pin(只连这些 IP),让"检查时的解析"与
    "实际连接的地址"是同一次结果 —— 否则域名解析可被攻击者在两次之间
    切换(DNS rebinding:检查时返回公网 IP、连接时返回内网 IP)。
    """
    if host.lower() in _BLOCKED_HOSTS:
        raise FetchError(f"目标地址被禁止(云元数据): {host}")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise FetchError(f"域名解析失败: {host} ({e})") from e

    checked: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        bare = ip_str.split("%")[0]  # 去掉 IPv6 zone id 再做类别判断
        try:
            ip = ipaddress.ip_address(bare)
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise FetchError(f"目标解析到受限地址({ip_str}),拒绝访问")
        checked.append(bare)
    return checked


def _validate_url(url: str) -> str:
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"只允许 http/https,收到: {parsed.scheme or '(无)'}")
    if not parsed.hostname:
        raise FetchError("URL 缺少主机名")
    _check_host(parsed.hostname)
    return url


def _split_host_port(host: str, default_port: int) -> tuple[str, int]:
    """从 req.host(可能是 host 或 host:port,IPv6 带 [])解析出名字和端口。"""
    if not host:
        return host, default_port
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return host, default_port
        hostname = host[1:end]
        rest = host[end + 1:]
        if rest.startswith(":"):
            try:
                return hostname, int(rest[1:])
            except ValueError:
                return hostname, default_port
        return hostname, default_port
    if ":" in host:
        hostname, _, port_s = host.rpartition(":")
        try:
            return hostname, int(port_s)
        except ValueError:
            return host, default_port
    return host, default_port


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """connect() 连到已校验的固定 IP,不再重复解析域名(DNS rebinding 防护)。"""

    _pinned_ip: str | None = None

    def connect(self) -> None:
        if not self._pinned_ip:
            return super().connect()
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """同上;TLS 握手仍用原域名(SNI 与证书验证保持正确)。"""

    _pinned_ip: str | None = None

    def connect(self) -> None:
        if not self._pinned_ip:
            return super().connect()
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


def _pin_ip_for(req: urllib.request.Request, default_port: int) -> str | None:
    """解析并检查目标 host,返回可 pin 的 IP。

    只对【直连】场景生效:连接目标(req.host)== URL 目标时,把校验过的
    IP 钉给连接层。走代理时(req.host 是代理地址)跳过 pin —— 连接目标
    是用户自己配置的代理基础设施,不归 SSRF 检查管;且不能拿 URL 的
    校验结果去 pin 代理连接。

    实测踩过的坑:不区分直连/代理时,本机 http_proxy=127.0.0.1:10809
    会让所有请求的 req.host 变成代理地址,被 SSRF 检查误拒。
    """
    parsed = urllib.parse.urlparse(req.get_full_url())
    hostname = parsed.hostname
    if not hostname:
        return None

    # 无论直连还是代理,URL 目标本身必须过检查(SSRF 拦截不因代理而豁免)
    checked = _check_host(hostname)

    # 连接目标与 URL 目标不同 → 走的是代理,跳过 pin
    conn_host, _ = _split_host_port(req.host or "", default_port)
    if not conn_host or conn_host.lower() != hostname.lower():
        return None
    return checked[0] if checked else None


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """建连前解析+检查,直连时把校验过的 IP 钉进连接类(不再二次解析)。"""

    def http_open(self, req):
        ip = _pin_ip_for(req, 80)
        cls = type("_PinnedHTTPConn", (_PinnedHTTPConnection,), {"_pinned_ip": ip})
        return self.do_open(cls, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """同上(HTTPS 版,context 透传给 TLS 层)。"""

    def https_open(self, req):
        ip = _pin_ip_for(req, 443)
        cls = type("_PinnedHTTPSConn", (_PinnedHTTPSConnection,), {"_pinned_ip": ip})
        return self.do_open(cls, req, context=self._context)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """重定向也是 SSRF 的入口:urlopen 默认自动跟随,落点不再过检查。

    实测绕过:初始 URL 是公网地址 → 302 到 http://127.0.0.1:port/ →
    默认行为直接打到内网。这里在每一跳把目标 URL 重新走一遍完整校验
    (scheme + host IP 类别),任何一跳落在禁区就抛错终止。
    """

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = newurl.replace(" ", "%20")
        if not newurl.lower().startswith(("http://", "https://")):
            raise FetchError(f"重定向到非 http(s) 地址,已阻断: {newurl[:100]}")

        # 每一跳都重新校验(这是修复的核心)
        try:
            _validate_url(newurl)
        except FetchError as e:
            raise FetchError(f"重定向被 SSRF 防护阻断({e})") from e

        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def _opener() -> urllib.request.OpenerDirector:
    """带 SSRF 防护的 opener:
    - 重定向每跳重校验(_SafeRedirectHandler)
    - 连接 pin 已校验 IP(_PinnedHTTP(S)Handler,防 DNS rebinding)
    """
    return urllib.request.build_opener(
        _SafeRedirectHandler(), _PinnedHTTPHandler(), _PinnedHTTPSHandler())


def _http_get(url: str) -> tuple[bytes, str, str]:
    """返回 (body, content_type, final_url)。大小与超时都有硬边界。

    重定向走 _SafeRedirectHandler:每一跳重新做 SSRF 校验,防止
    "公网跳板 → 302 → 内网"的绕过。
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with _opener().open(req, timeout=TIMEOUT) as resp:
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError(f"响应超过 {MAX_BYTES} 字节上限,已中止")
            return body, ctype, resp.geturl()
    except FetchError:
        raise
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        # 重定向处理器里抛的 FetchError 会被 urllib 包进 URLError.reason
        if isinstance(e.reason, FetchError):
            raise e.reason
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
