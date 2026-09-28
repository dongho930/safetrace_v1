"""검문 프록시(SSRF 2차 방어). 격리 네트워크의 브라우저가 외부로 나가는 유일한 출구.

- CONNECT(HTTPS)와 절대 URI(HTTP)만 받는다.
- 접속 시점에 직접 DNS 를 해석하고, 모든 IP 가 공인 IP 일 때만 '검사한 그 IP'로 연결한다(DNS Rebinding 방지).
- 포트는 허용 목록(기본 80/443)만.
- 실행: python -m safetrace.proxy.egress --port 3128
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from urllib.parse import parse_qs, urlsplit

from ..netguard import BlockedURL, is_public_ip, resolve

log = logging.getLogger("safetrace.egress")

MAX_HEADER = 16 * 1024
IDLE_TIMEOUT = 60


class Policy:
    def __init__(self, allowed_ports: set[int], test_allowlist: set[str]):
        self.allowed_ports = allowed_ports
        self.test_allowlist = test_allowlist

    def pick_ip(self, host: str, port: int) -> str:
        host = host.strip("[]").rstrip(".").lower()
        if f"{host}:{port}" in self.test_allowlist:
            return resolve(host, port)[0]
        if port not in self.allowed_ports:
            raise BlockedURL("port_not_allowed", str(port))
        ips = resolve(host, port)
        for ip in ips:
            if not is_public_ip(ip):
                raise BlockedURL("non_public_ip", f"{host} -> {ip}")
        return ips[0]


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        while True:
            data = await asyncio.wait_for(r.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            w.write(data)
            await w.drain()
    except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


def _split_hostport(s: str, default_port: int) -> tuple[str, int]:
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if s.count(":") == 1:
        h, p = s.split(":")
        return h, int(p)
    return s, default_port


class EgressProxy:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.blocked = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, TimeoutError):
            writer.close()
            return
        if len(head) > MAX_HEADER:
            await self._deny(writer, 431, "header_too_large")
            return
        try:
            line, *hdr_lines = head.decode("latin-1").split("\r\n")
            method, target, version = line.split(" ", 2)
        except ValueError:
            await self._deny(writer, 400, "bad_request")
            return
        try:
            if method.upper() == "CONNECT":
                host, port = _split_hostport(target, 443)
                ip = await asyncio.to_thread(self.policy.pick_ip, host, port)
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                if not target.lower().startswith("http://"):
                    await self._deny(writer, 400, "absolute_http_uri_required")
                    return
                rest = target[7:]
                hostport, _, path = rest.partition("/")
                host, port = _split_hostport(hostport, 80)
                ip = await asyncio.to_thread(self.policy.pick_ip, host, port)
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
                kept = [h for h in hdr_lines if h and not h.lower().startswith(("proxy-", "connection:"))]
                req = f"{method} /{path} {version}\r\n" + "\r\n".join(kept) + "\r\nConnection: close\r\n\r\n"
                up_w.write(req.encode("latin-1"))
                await up_w.drain()
        except BlockedURL as e:
            self.blocked += 1
            log.warning("egress blocked %s: %s", target[:200], e.reason)
            await self._deny(writer, 403, e.reason)
            return
        except (OSError, TimeoutError, ValueError):
            await self._deny(writer, 502, "upstream_unreachable")
            return
        await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))

    async def _deny(self, writer: asyncio.StreamWriter, code: int, reason: str):
        body = f"blocked by safetrace egress: {reason}\n".encode()
        writer.write(f"HTTP/1.1 {code} Blocked\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                     f"Connection: close\r\n\r\n".encode() + body)
        try:
            await writer.drain()
        finally:
            writer.close()


async def handle_resolve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """격리망 안의 에이전트가 1차 IP 확인에 쓰는 DNS 조회 전용 엔드포인트.

    GET /resolve?host=<host>&port=<port>  →  {"ips": [...]} 또는 {"error": "dns_failure"}
    판정(공인 IP 여부)은 에이전트가 직접 하고, 실제 연결 시점에는 프록시가 다시 해석·검사한다.
    """
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        line = raw.split(b"\r\n", 1)[0].decode("latin-1")
        method, target, _ = line.split(" ", 2)
        parts = urlsplit(target)
        q = parse_qs(parts.query)
        if method != "GET" or parts.path != "/resolve" or "host" not in q:
            raise ValueError
        host = q["host"][0][:253]
        port = int(q.get("port", ["443"])[0])
        try:
            body = {"ips": list(await asyncio.to_thread(resolve, host, port))}
        except BlockedURL:
            body = {"error": "dns_failure"}
        code = 200
    except (ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        body, code = {"error": "bad_request"}, 400
    data = json.dumps(body).encode()
    writer.write(f"HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
                 f"Connection: close\r\n\r\n".encode() + data)
    try:
        await writer.drain()
    finally:
        writer.close()


async def serve(host: str, port: int, policy: Policy, resolve_port: int | None = None):
    proxy = EgressProxy(policy)
    server = await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEADER)
    log.info("egress proxy on %s:%s", host, port)
    servers = [server]
    if resolve_port:
        servers.append(await asyncio.start_server(handle_resolve, host, resolve_port, limit=4096))
        log.info("resolver on %s:%s", host, resolve_port)
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main():
    logging.basicConfig(level=logging.INFO)
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")  # 컨테이너에서는 --host 로 명시
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--resolve-port", type=int, default=3129)
    a = ap.parse_args()
    ports = {int(p) for p in os.environ.get("ST_EGRESS_PORTS", "80,443").split(",") if p}
    allow = {x for x in os.environ.get("ST_EGRESS_TEST_ALLOWLIST", "").split(",") if x}
    asyncio.run(serve(a.host, a.port, Policy(ports, allow), a.resolve_port))


if __name__ == "__main__":
    main()
