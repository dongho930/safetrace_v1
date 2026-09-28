"""SSRF 1차 방어: 이동 전에 URL을 검사하고 실제 IP를 확인한다.

2차 방어는 egress 프록시(proxy/egress.py)가 접속 시점에 다시 해석한 IP로 검사한다.
DNS Rebinding 대비: 여기서 확인한 IP를 믿고 끝내지 않고, 실제 연결 시점마다 재검증한다.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048

# is_global 로 걸러지지 않는 대역을 명시적으로 추가 차단
_EXTRA_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "192.0.0.0/24",
        "198.18.0.0/15",  # 벤치마크
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",  # NAT64 (내부 IPv4로 우회 가능)
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]


class BlockedURL(Exception):
    """정책상 접속할 수 없는 URL. reason 은 사용자에게 보여도 되는 짧은 코드다."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    ips: tuple[str, ...]
    allowlisted: bool = False


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if not addr.is_global:
        return False
    return not any(addr in net for net in _EXTRA_BLOCKED)


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise BlockedURL("invalid_host")
    try:
        return host.encode("idna").decode("ascii") if not _is_ip_literal(host) else host
    except UnicodeError as e:
        raise BlockedURL("invalid_host") from e


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_url(url: str, allowed_ports: list[int]) -> tuple[str, str, int]:
    if len(url) > MAX_URL_LENGTH:
        raise BlockedURL("url_too_long")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedURL("scheme_not_allowed", scheme)
    if parts.username or parts.password:
        raise BlockedURL("credentials_in_url")
    if not parts.hostname:
        raise BlockedURL("invalid_host")
    host = _normalize_host(parts.hostname)
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as e:
        raise BlockedURL("invalid_port") from e
    return scheme, host, port


def resolve(host: str, port: int) -> tuple[str, ...]:
    if _is_ip_literal(host):
        return (host,)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise BlockedURL("dns_failure", host) from e
    ips = tuple(dict.fromkeys(info[4][0] for info in infos))
    if not ips:
        raise BlockedURL("dns_failure", host)
    return ips


def remote_resolver(base_url: str, timeout_s: float = 5.0):
    """격리망에서 egress 의 DNS 조회 엔드포인트를 쓰는 resolver. 공인 IP 판정은 호출자가 한다."""
    import httpx  # noqa: PLC0415

    client = httpx.Client(base_url=base_url, timeout=timeout_s, trust_env=False, follow_redirects=False)

    def _resolve(host: str, port: int) -> tuple[str, ...]:
        if _is_ip_literal(host):
            return (host,)
        try:
            r = client.get("/resolve", params={"host": host, "port": port})
            ips = r.json().get("ips") if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError) as e:
            raise BlockedURL("dns_failure", host) from e
        if not ips or not all(isinstance(ip, str) for ip in ips):
            raise BlockedURL("dns_failure", host)
        for ip in ips:
            ipaddress.ip_address(ip)  # 형식 검증
        return tuple(ips)

    return _resolve


def check_url(
    url: str,
    allowed_ports: list[int],
    test_allowlist: list[str] | None = None,
    resolver=resolve,
) -> Target:
    """URL 을 검사해 접속 대상 정보를 돌려준다. 하나라도 사설·예약 IP면 차단한다."""
    scheme, host, port = parse_url(url, allowed_ports)
    if test_allowlist and f"{host}:{port}" in test_allowlist:
        return Target(scheme, host, port, (), allowlisted=True)
    if port not in allowed_ports:
        raise BlockedURL("port_not_allowed", str(port))
    ips = resolver(host, port)
    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedURL("non_public_ip", f"{host} -> {ip}")
    return Target(scheme, host, port, ips)
