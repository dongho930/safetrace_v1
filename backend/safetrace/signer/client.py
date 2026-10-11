"""서명 서비스 클라이언트. 에이전트는 RemoteSealer(기록 추가만), API 는 ChainAdmin(열기·닫기·head)을 쓴다."""

from __future__ import annotations

import httpx

from ..evidence import Head


class SignerError(Exception):
    pass


def _client(base_url: str, token: str, timeout_s: float, client: httpx.Client | None) -> httpx.Client:
    c = client or httpx.Client(base_url=base_url, timeout=timeout_s)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


class RemoteSealer:
    """에이전트 쪽: 기록 내용을 보내고 서명된 기록을 받는다. 키는 갖지 않는다."""

    def __init__(self, base_url: str, token: str, timeout_s: float = 5.0, client: httpx.Client | None = None):
        self._c = _client(base_url, token, timeout_s, client)

    def seal(self, case_id: str, head: Head, kind: str, data: dict, files: dict[str, str]) -> dict:
        body = {"seq": head.seq + 1, "kind": kind, "data": data, "files": files}
        last: Exception | None = None
        # 연결이 끊겨 응답을 못 받았으면 같은 내용으로 한 번 더 보낸다. 서비스가 이미 만든 기록을 돌려준다
        for _ in range(2):
            try:
                r = self._c.post(f"/v1/chains/{case_id}/records", json=body)
            except httpx.TransportError as e:
                last = e
                continue
            if r.status_code != 200:
                raise SignerError(f"signer refused: {r.status_code} {r.text[:200]}")
            return r.json()
        raise SignerError(f"signer unreachable: {type(last).__name__}")


class ChainAdmin:
    """API 쪽: 접수 때 체인을 열고, 조사가 끝나면 닫아 head 를 받는다."""

    def __init__(self, base_url: str, token: str, timeout_s: float = 5.0, client: httpx.Client | None = None):
        self._c = _client(base_url, token, timeout_s, client)

    def _call(self, method: str, case_id: str, op: str) -> dict:
        try:
            r = self._c.request(method, f"/v1/chains/{case_id}/{op}")
        except httpx.HTTPError as e:
            raise SignerError(f"signer unreachable: {type(e).__name__}") from None
        if r.status_code != 200:
            raise SignerError(f"signer refused: {r.status_code}")
        return r.json()

    def open(self, case_id: str) -> dict:
        return self._call("POST", case_id, "open")

    def close(self, case_id: str) -> dict:
        return self._call("POST", case_id, "close")

    def head(self, case_id: str) -> dict:
        return self._call("GET", case_id, "head")
