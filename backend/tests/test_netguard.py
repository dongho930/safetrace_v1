import pytest

from safetrace.netguard import BlockedURL, check_url, is_public_ip

PORTS = [80, 443]


def fake_resolver(mapping):
    return lambda host, port: tuple(mapping[host])


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
    "224.0.0.1", "198.18.0.1",
])
def test_private_ips_are_not_public(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize("url,reason", [
    ("file:///etc/passwd", "scheme_not_allowed"),
    ("javascript:alert(1)", "scheme_not_allowed"),
    ("ftp://example.com/", "scheme_not_allowed"),
    ("http://user:pw@example.com/", "credentials_in_url"),
    ("http://example.com:22/", "port_not_allowed"),
    ("http://127.0.0.1/", "non_public_ip"),
    ("http://[::1]/", "non_public_ip"),
    ("http://169.254.169.254/latest/meta-data/", "non_public_ip"),
    ("http://2130706433/", "non_public_ip"),  # 10진수 IP 표기
])
def test_blocked_urls(url, reason):
    with pytest.raises(BlockedURL) as e:
        check_url(url, PORTS, resolver=lambda h, p: ("127.0.0.1",) if h == "2130706433" else (h,))
    assert e.value.reason == reason


def test_dns_to_private_blocked():
    r = fake_resolver({"evil.example": ["93.184.216.34", "10.0.0.5"]})
    with pytest.raises(BlockedURL) as e:
        check_url("https://evil.example/", PORTS, resolver=r)
    assert e.value.reason == "non_public_ip"


def test_public_ok():
    t = check_url("https://good.example/a?b=1", PORTS, resolver=fake_resolver({"good.example": ["93.184.216.34"]}))
    assert t.ips == ("93.184.216.34",)


def test_allowlist_only_exact_hostport():
    t = check_url("http://127.0.0.1:8900/x", PORTS, ["127.0.0.1:8900"])
    assert t.allowlisted
    with pytest.raises(BlockedURL):
        check_url("http://127.0.0.1:8901/x", PORTS, ["127.0.0.1:8900"])


def test_idn_host_normalized():
    seen = []
    check_url("https://한국.example/", PORTS, resolver=lambda h, p: seen.append(h) or ("93.184.216.34",))
    assert seen == ["xn--3e0b707e.example"]
