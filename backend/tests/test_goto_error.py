import pytest
from playwright.async_api import Error as PWError
from playwright.async_api import TimeoutError as PWTimeout

from safetrace.agent.loop import classify_goto_error


@pytest.mark.parametrize("msg, code, category", [
    ("net::ERR_NAME_NOT_RESOLVED at https://gone.example/", "ERR_NAME_NOT_RESOLVED", "dns_failure"),
    ("net::ERR_EMPTY_RESPONSE at http://x.example/", "ERR_EMPTY_RESPONSE", "connection_dropped"),
    ("net::ERR_CONNECTION_RESET at http://x.example/", "ERR_CONNECTION_RESET", "connection_dropped"),
    ("net::ERR_TUNNEL_CONNECTION_FAILED at https://x.example/", "ERR_TUNNEL_CONNECTION_FAILED", "egress_refused"),
    ("net::ERR_CERT_AUTHORITY_INVALID at https://x.example/", "ERR_CERT_AUTHORITY_INVALID", "tls_error"),
    ("net::ERR_BLOCKED_BY_CLIENT at http://10.0.0.1/", "ERR_BLOCKED_BY_CLIENT", "blocked_by_policy"),
    ("net::ERR_SOMETHING_NEW at http://x.example/", "ERR_SOMETHING_NEW", "other"),
    ("Target page, context or browser has been closed", None, "other"),
])
def test_classify(msg, code, category):
    out = classify_goto_error(PWError(msg))
    assert out == {"error": "Error", "net_error": code, "category": category}
    assert "x.example" not in str(out)  # URL 등 오류 문구는 남기지 않는다


def test_timeout():
    assert classify_goto_error(PWTimeout("Timeout 15000ms exceeded."))["category"] == "timeout"
