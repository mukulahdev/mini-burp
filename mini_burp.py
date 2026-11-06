#!/usr/bin/env python3
"""mini_burp: a tiny HTTP proxy that shows and checks your own traffic.

Built line by line in the MUKULAH Dev course "Burp Suite", part 3,
by Romeo Mukulah and Claude. It forwards plain HTTP between your
browser and a lab server, keeps a history like Burp's, hides secrets,
and warns about missing security headers and exposed login cookies.
It only talks to private lab addresses, and it never changes traffic.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import shutil
import socket
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SECRET_KEYS = {"password", "passwordrepeat", "token", "otp", "code"}
LOGIN_COOKIES = {"token", "session", "sessionid", "auth"}
HOP_HEADERS = {"connection", "keep-alive", "proxy-connection", "te",
               "trailer", "transfer-encoding", "upgrade"}
WANTED = ["X-Content-Type-Options", "X-Frame-Options",
          "Content-Security-Policy"]

QUIET = re.compile(r"/socket\.io/|\.(js|css|png|jpe?g|avif|svg|ico|woff2?)$")

history: list[dict] = []
findings: dict[str, int] = {}
hosts: set[str] = set()

# ---------------------------------------------------------------- colours

COLOR = sys.stdout.isatty()
PAINT = {"dim": "2", "bold": "1", "red": "91", "green": "92",
         "amber": "93", "blue": "94", "pink": "95", "cyan": "96",
         "orange": "38;5;208"}
METHODS = {"GET": "cyan", "POST": "amber", "PUT": "blue", "DELETE": "red"}


def paint(text: str, *styles: str) -> str:
    """Wrap text in terminal colours (only on a real terminal)."""
    if not COLOR:
        return text
    codes = ";".join(PAINT[s] for s in styles)
    return f"\033[{codes}m{text}\033[0m"


def banner(port: int) -> str:
    """The welcome box, drawn with box characters."""
    lines = ["M I N I   B U R P   ·   your own traffic, checked",
             "designed by Romeo Mukulah & Claude  ·  MUKULAH Dev"]
    width = max(len(line) for line in lines) + 4
    edge = paint("│", "orange")
    styles = [("bold", "orange"), ("bold", "cyan")]
    rows = [edge + "  " + paint(line.ljust(width - 2), *style) + edge
            for line, style in zip(lines, styles)]
    hint = (f"  listening on 127.0.0.1:{port}  ·  lab addresses only"
            "  ·  Ctrl+C to stop")
    return "\n".join([paint("╭" + "─" * width + "╮", "orange"), *rows,
                      paint("╰" + "─" * width + "╯", "orange"),
                      paint(hint, "dim"), ""])

# ---------------------------------------------------------------- checks


def lab_only(host: str) -> bool:
    """Allow private lab addresses only, never the internet."""
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except (OSError, ValueError):
        return False


def mask(body: bytes) -> str:
    """A request body with every secret value replaced by ***."""
    text = body.decode(errors="replace")
    try:
        data = json.loads(text)
    except ValueError:
        pattern = r"((?:password|token|otp|code)=)[^&]*"
        return re.sub(pattern, r"\1***", text, flags=re.I)
    if isinstance(data, dict):
        for key in data:
            if key.lower() in SECRET_KEYS:
                data[key] = "***"
    return json.dumps(data)


def request_notes(headers) -> list[str]:
    """Login secrets this request sends over plain HTTP, never shown."""
    notes = []
    for part in (headers.get("Cookie") or "").split(";"):
        name = part.split("=", 1)[0].strip()
        if name.lower() in LOGIN_COOKIES:
            notes.append(f"login cookie '{name}' sent over plain HTTP"
                         " (value hidden)")
    if headers.get("Authorization"):
        notes.append("Authorization header sent over plain HTTP"
                     " (value hidden)")
    return notes


def audit(headers) -> list[str]:
    """Missing security headers and cookie flags in one response."""
    found = {name.lower() for name in headers.keys()}
    notes = [f"missing {h}" for h in WANTED if h.lower() not in found]
    for cookie in headers.get_all("Set-Cookie") or []:
        name = cookie.split("=", 1)[0]
        for flag in ("HttpOnly", "SameSite"):
            if flag.lower() not in cookie.lower():
                notes.append(f"cookie {name} without {flag}")
    return notes

# ---------------------------------------------------------------- history


def record(method, url, status, body, notes, length) -> None:
    """Add one row to the history and print it, secrets hidden."""
    entry = {"n": len(history) + 1,
             "time": datetime.now().strftime("%H:%M:%S"),
             "method": method, "url": url, "status": status,
             "length": length, "notes": notes}
    where = urlsplit(url)
    entry["quiet"] = bool(QUIET.search(where.path))
    history.append(entry)
    for note in notes:
        findings[note] = findings.get(note, 0) + 1
    if entry["quiet"]:
        return
    if where.netloc not in hosts:
        hosts.add(where.netloc)
        print(paint(f"  ── {where.netloc} " + "─" * 30, "orange"))
    path = where.path + (f"?{where.query}" if where.query else "")
    room = shutil.get_terminal_size().columns - 34
    if len(path) > room:
        path = path[:room - 1] + "…"
    colour = "green" if status < 300 else "amber" if status < 400 else "red"
    num = paint(f"#{entry['n']:<4}", "dim")
    verb = paint(f"{method:<6}", "bold", METHODS.get(method, "cyan"))
    code = paint(str(status), "bold", colour)
    size = paint(f"{length} B", "dim")
    print(f" {num}{entry['time']}  {verb} {code}  {path}  {size}")
    if body:
        print(f"       {paint('▸ body', 'pink')}  {mask(body)}")
    for note in notes:
        if findings[note] == 1:
            print(f"       {paint('⚠ ' + note, 'amber')}")


def summary() -> str:
    """The report printed when you stop the proxy."""
    quiet = sum(1 for entry in history if entry["quiet"])
    lines = ["", paint(f"  {len(history)} requests recorded", "bold"),
             paint(f"  {quiet} background requests hidden"
                   " (images, scripts, live chat)", "dim")]
    for note, count in sorted(findings.items(), key=lambda x: -x[1]):
        lines.append(f"  {paint('⚠', 'amber')} {note}  "
                     + paint(f"x{count}", "dim"))
    if not findings:
        lines.append(paint("  ✔ no findings", "green"))
    return "\n".join(lines)

# ---------------------------------------------------------------- proxy


class Proxy(BaseHTTPRequestHandler):
    """Receives each browser request and forwards it to the lab."""

    def do_GET(self) -> None:
        self.forward()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET

    def do_CONNECT(self) -> None:
        self.send_error(501, "mini Burp only watches plain HTTP")

    def forward(self) -> None:
        url = urlsplit(self.path)
        if url.scheme != "http" or not url.hostname:
            self.send_error(400, "send absolute http:// URLs")
            return
        if not lab_only(url.hostname):
            self.send_error(403, "lab addresses only")
            return
        size = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(size)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_HEADERS}
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        conn = http.client.HTTPConnection(url.hostname, url.port or 80,
                                          timeout=10)
        conn.request(self.command, path, body or None, headers)
        reply = conn.getresponse()
        data = reply.read()
        conn.close()
        notes = request_notes(self.headers) + audit(reply.headers)
        record(self.command, self.path, reply.status, body, notes,
               len(data))
        self.send_response_only(reply.status, reply.reason)
        for k, v in reply.headers.items():
            if k.lower() not in HOP_HEADERS | {"content-length"}:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, *args) -> None:
        """Silence the default log; record() prints our own."""


def main(port: int = 8081) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Proxy)
    print(banner(port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(summary())
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
