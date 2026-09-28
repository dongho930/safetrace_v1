import httpx

from safetrace.safebrowsing import lookup


def test_not_configured_is_not_safe():
    assert lookup(["https://x.example/"], "")["status"] == "not_configured"


def test_match_and_key_in_header():
    seen = {}

    def handler(req: httpx.Request):
        seen["key"] = req.headers.get("x-goog-api-key")
        seen["query"] = str(req.url.query)
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING",
                                                      "threat": {"url": "https://x.example/"}}]})

    r = lookup(["https://x.example/", "javascript:alert(1)"], "KEY", transport=httpx.MockTransport(handler))
    assert r["status"] == "match" and r["matches"][0]["threat_type"] == "SOCIAL_ENGINEERING"
    assert seen["key"] == "KEY" and "KEY" not in seen["query"]


def test_no_match_and_error():
    ok = httpx.MockTransport(lambda req: httpx.Response(200, json={}))
    assert lookup(["https://x.example/"], "K", transport=ok)["status"] == "no_match"
    bad = httpx.MockTransport(lambda req: httpx.Response(500))
    assert lookup(["https://x.example/"], "K", transport=bad)["status"] == "error"
