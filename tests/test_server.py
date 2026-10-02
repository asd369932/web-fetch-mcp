"""web-fetch-mcp 的 SSRF 防护与抓取测试。

不依赖外网:用本地 HTTP server 提供内容,同时验证本地地址确实被 SSRF 规则拦截
(测试里显式放行 127.0.0.1 通过 monkeypatch 替换检查函数来测抓取逻辑)。
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import web_fetch_mcp.server as srv  # noqa: E402


# ---------------------------------------------------------------------------
# 本地测试服务器
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静音
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/json":
            body = json.dumps({"ok": True, "items": [1, 2, 3]}).encode()
            ctype = "application/json"
        elif self.path == "/plain":
            body = b"just plain text"
            ctype = "text/plain; charset=utf-8"
        elif self.path == "/links":
            body = b'<html><body><a href="/a">A</a><a href="http://x.test/b">B</a></body></html>'
            ctype = "text/html"
        elif self.path == "/long":
            body = ("<html><body><p>" + "word " * 500 + "</p></body></html>").encode()
            ctype = "text/html; charset=utf-8"
        else:
            body = (b"<html><head><title>Test Page</title>"
                    b"<style>body{color:red}</style>"
                    b"<script>alert(1)</script></head>"
                    b"<body><h1>Hello</h1><p>World</p></body></html>")
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def http_server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


@pytest.fixture()
def allow_local(monkeypatch: pytest.MonkeyPatch):
    """放行本地地址,让抓取逻辑本身可被测试(SSRF 规则另有独立测试)。"""
    monkeypatch.setattr(srv, "_check_host", lambda host: None)


# ---------------------------------------------------------------------------
# SSRF 防护(核心安全边界)
# ---------------------------------------------------------------------------

class TestSSRFGuard:
    def test_metadata_ip_blocked(self) -> None:
        assert "云元数据" in srv.fetch("http://169.254.169.254/latest/meta-data/")

    def test_metadata_hostname_blocked(self) -> None:
        assert "云元数据" in srv.fetch("http://metadata.google.internal/")

    def test_aliyun_metadata_blocked(self) -> None:
        assert "云元数据" in srv.fetch("http://100.100.100.200/")

    def test_loopback_blocked(self) -> None:
        out = srv.fetch("http://127.0.0.1:8899/")
        assert "受限地址" in out

    def test_localhost_name_blocked(self) -> None:
        out = srv.fetch("http://localhost/")
        assert "受限地址" in out

    def test_private_ip_blocked(self) -> None:
        out = srv.fetch("http://192.168.1.1/")
        assert "受限地址" in out

    def test_private_ip_10_blocked(self) -> None:
        assert "受限地址" in srv.fetch("http://10.0.0.1/")

    def test_link_local_blocked(self) -> None:
        assert "受限地址" in srv.fetch("http://169.254.1.1/")

    def test_ipv6_loopback_blocked(self) -> None:
        out = srv.fetch("http://[::1]/")
        assert "受限地址" in out

    def test_file_scheme_rejected(self) -> None:
        assert "http/https" in srv.fetch("file:///etc/passwd")

    def test_gopher_scheme_rejected(self) -> None:
        assert "http/https" in srv.fetch("gopher://x/")

    def test_ftp_scheme_rejected(self) -> None:
        assert "http/https" in srv.fetch("ftp://example.com/x")

    def test_missing_hostname(self) -> None:
        assert "主机名" in srv.fetch("http:///nohost")

    def test_fetch_json_also_guarded(self) -> None:
        assert "受限地址" in srv.fetch_json("http://127.0.0.1/")

    def test_extract_links_also_guarded(self) -> None:
        assert "受限地址" in srv.extract_links("http://192.168.0.1/")


# ---------------------------------------------------------------------------
# 抓取逻辑(本地服务器)
# ---------------------------------------------------------------------------

class TestFetchLogic:
    def test_html_stripped(self, http_server, allow_local) -> None:
        out = srv.fetch(http_server + "/")
        assert "Hello" in out
        assert "World" in out
        assert "alert(1)" not in out          # script 被去掉
        assert "color:red" not in out         # style 被去掉
        assert "Test Page" in out             # 标题提取

    def test_truncation(self, http_server, allow_local) -> None:
        # /long 返回 2500 字符正文,缩到 100 必触发截断
        out = srv.fetch(http_server + "/long", max_chars=100)
        assert "截断" in out
        assert out.count("word") < 50

    def test_json_formatted(self, http_server, allow_local) -> None:
        out = srv.fetch_json(http_server + "/json")
        data = json.loads(out.split("\n", 2)[2])
        assert data["ok"] is True
        assert data["items"] == [1, 2, 3]

    def test_non_json_preview(self, http_server, allow_local) -> None:
        out = srv.fetch_json(http_server + "/plain")
        assert "非 JSON" in out
        assert "just plain text" in out

    def test_links_absolutized(self, http_server, allow_local) -> None:
        out = json.loads(srv.extract_links(http_server + "/links"))
        urls = [l["url"] for l in out["links"]]
        assert any(u.startswith(http_server + "/a") for u in urls)  # 相对转绝对
        assert "http://x.test/b" in urls
        assert out["links"][0]["text"] == "A"

    def test_connection_error(self, allow_local) -> None:
        out = srv.fetch("http://127.0.0.1:1/")  # 端口 1 必不通
        assert "[拒绝/失败]" in out


# ---------------------------------------------------------------------------
# 重定向 SSRF(回归:verify 子代理实测的绕过)
# ---------------------------------------------------------------------------

class _Redirector(BaseHTTPRequestHandler):
    """302 跳板:GET 什么路径都跳到构造时指定的目标。"""

    target = ""

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")  # 没这行 urllib 读体会撞连接重置
        self.end_headers()


class TestRedirectSSRF:
    """重定向不能成为 SSRF 的旁路。

    实测绕过:初始 URL 被放行 → 服务器 302 到 127.0.0.1 →
    默认 urlopen 直接打到内网。修复后每一跳都重新校验。

    测试用两个 loopback 地址区分角色:
      127.0.0.2 = 模拟"外部可访问的跳板"(patch 后放行)
      127.0.0.1 = 模拟"内网敏感目标"(真实规则会拦)
    """

    @pytest.fixture()
    def servers(self):
        # 敏感目标:127.0.0.1
        inner = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=inner.serve_forever, daemon=True).start()

        # 跳板:127.0.0.2
        class _R(_Redirector):
            target = f"http://127.0.0.1:{inner.server_port}/"

        redirector = HTTPServer(("127.0.0.2", 0), _R)
        threading.Thread(target=redirector.serve_forever, daemon=True).start()

        yield {
            "inner_url": f"http://127.0.0.1:{inner.server_port}/",
            "redirect_url": f"http://127.0.0.2:{redirector.server_port}/",
        }
        redirector.shutdown()
        inner.shutdown()

    @pytest.fixture()
    def allow_relay_only(self, monkeypatch: pytest.MonkeyPatch):
        """模拟"跳板地址在允许列表里,其余按真实规则拦"。"""
        real_check = srv._check_host

        def patched(host: str) -> None:
            if host == "127.0.0.2":
                return  # 跳板被放行(模拟它在公网/白名单)
            real_check(host)  # 127.0.0.1 走真实校验 → 拦截

        monkeypatch.setattr(srv, "_check_host", patched)

    def test_redirect_to_loopback_blocked(self, servers, allow_relay_only) -> None:
        out = srv.fetch(servers["redirect_url"])
        assert "[拒绝/失败]" in out or "阻断" in out, f"重定向 SSRF 未被拦截: {out[:200]}"
        assert "Hello" not in out and "World" not in out

    def test_redirect_chain_revalidates_each_hop(self, servers, monkeypatch: pytest.MonkeyPatch) -> None:
        """断言 _check_host 在重定向后被再次调用 —— 证明是"每一跳校验"而非只看初始 URL。"""
        calls: list[str] = []
        real_check = srv._check_host

        def patched(host: str) -> None:
            calls.append(host)
            if host == "127.0.0.2":
                return
            real_check(host)

        monkeypatch.setattr(srv, "_check_host", patched)
        srv.fetch(servers["redirect_url"])

        assert "127.0.0.2" in calls, "初始 URL 未检查"
        assert "127.0.0.1" in calls, f"重定向落点未被重新检查(只检查了初始 URL)。调用记录: {calls}"

    def test_normal_redirect_still_works(self, http_server, monkeypatch: pytest.MonkeyPatch) -> None:
        """修复不能把正常重定向弄坏:跳板→允许的地址应正常返回内容。"""
        # 目标也在"允许"范围(127.0.0.3 同时扮演两边的放行角色)
        inner = HTTPServer(("127.0.0.3", 0), Handler)
        threading.Thread(target=inner.serve_forever, daemon=True).start()

        class _R(_Redirector):
            target = f"http://127.0.0.3:{inner.server_port}/"

        redirector = HTTPServer(("127.0.0.2", 0), _R)
        threading.Thread(target=redirector.serve_forever, daemon=True).start()

        def patched(host: str) -> None:
            if host in ("127.0.0.2", "127.0.0.3"):
                return
            srv._check_host(host)

        monkeypatch.setattr(srv, "_check_host", patched)
        try:
            out = srv.fetch(f"http://127.0.0.2:{redirector.server_port}/")
            assert "Hello" in out, f"正常重定向被误伤: {out[:200]}"
        finally:
            redirector.shutdown()
            inner.shutdown()
