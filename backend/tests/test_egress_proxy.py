"""검문 프록시: 접속 시점 재해석 + 사설 IP 차단(DNS Rebinding 대비)."""

import asyncio

import pytest

from safetrace.netguard import BlockedURL
from safetrace.proxy import egress
from safetrace.proxy.egress import EgressProxy, Policy


def test_policy_blocks_private_and_ports(monkeypatch):
    answers = {"rebind.example": [("93.184.216.34",), ("127.0.0.1",)]}

    def fake_resolve(host, port):
        return answers[host].pop(0)

    monkeypatch.setattr(egress, "resolve", fake_resolve)
    pol = Policy({80, 443}, set())
    # 1차 해석은 공인 IP, 접속 시점 재해석은 127.0.0.1 → 두 번째에서 차단
    assert pol.pick_ip("rebind.example", 443) == "93.184.216.34"
    with pytest.raises(BlockedURL):
        pol.pick_ip("rebind.example", 443)
    with pytest.raises(BlockedURL):
        pol.pick_ip("8.8.8.8", 22)


async def _request(port: int, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    data = await asyncio.wait_for(r.read(4096), 5)
    w.close()
    return data


def test_proxy_denies_internal_connect():
    async def main():
        proxy = EgressProxy(Policy({80, 443}, set()))
        srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            a = await _request(port, b"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            b = await _request(port, b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            c = await _request(port, b"GET /relative HTTP/1.1\r\nHost: x\r\n\r\n")
            d = await _request(port, b"CONNECT 10.0.0.1:22 HTTP/1.1\r\n\r\n")
        return a, b, c, d

    a, b, c, d = asyncio.run(main())
    assert a.startswith(b"HTTP/1.1 403") and b"non_public_ip" in a
    assert b.startswith(b"HTTP/1.1 403")
    assert c.startswith(b"HTTP/1.1 400")
    assert d.startswith(b"HTTP/1.1 403") and b"port_not_allowed" in d


def test_resolver_endpoint_and_remote_resolver():
    import threading

    from safetrace.netguard import check_url, remote_resolver

    loop = asyncio.new_event_loop()
    ready = threading.Event()
    port_box = {}

    async def start():
        srv = await asyncio.start_server(egress.handle_resolve, "127.0.0.1", 0)
        port_box["p"] = srv.sockets[0].getsockname()[1]
        ready.set()
        await srv.serve_forever()

    t = threading.Thread(target=lambda: loop.run_until_complete(start()), daemon=True)
    t.start()
    ready.wait(5)
    res = remote_resolver(f"http://127.0.0.1:{port_box['p']}")
    assert "127.0.0.1" in res("localhost", 80)
    with pytest.raises(BlockedURL) as e:
        check_url("http://localhost/", [80, 443], resolver=res)
    assert e.value.reason == "non_public_ip"
    with pytest.raises(BlockedURL):
        res("nonexistent.invalid", 80)
    loop.call_soon_threadsafe(loop.stop)
