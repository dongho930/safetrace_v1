"""Jev 실연결 점검: API 키가 준비되면 한 번 실행해 요청 형식·응답 파싱·지연 시간을 확인한다.

실행: ST_TYPESAFE_API_KEY=... python tools/jev_smoke.py            (TypeSafe 직접)
      ST_OPENROUTER_API_KEY=... python tools/jev_smoke.py --openrouter
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from safetrace.config import get_settings  # noqa: E402
from safetrace.decision.engine import Engine  # noqa: E402
from safetrace.decision.providers import JevProvider  # noqa: E402
from safetrace.decision.schema import ActionRequest, Candidate, PageState, ThreatRequest  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--openrouter", action="store_true")
    a = ap.parse_args()
    s = get_settings()
    if a.openrouter:
        p = JevProvider("jev_openrouter", s.openrouter_base_url, s.openrouter_api_key.get_secret_value(),
                        s.openrouter_jev_model, s.decision_timeout_s)
    else:
        p = JevProvider("jev_typesafe", s.typesafe_base_url, s.typesafe_api_key.get_secret_value(),
                        s.jev_model, s.decision_timeout_s)
    eng = Engine([p], s.action_min_prob, s.threat_min_prob)
    state = PageState(step=0, url="https://usim-free.example/", title="유심 무상 교체 신청 안내",
                      text="최근 보안 사고와 관련해 전 고객 유심을 무상 교체해 드립니다. 아래 버튼을 눌러 신청하세요.",
                      candidates=[Candidate(id="e0", tag="a", text="무상 교체 신청하기"),
                                  Candidate(id="e1", tag="a", text="개인정보처리방침")])
    d = eng.decide_action(ActionRequest(state=state))
    print("action:", d.choice, d.probabilities, d.model, f"{d.latency_ms}ms")
    t = eng.decide_threat(ThreatRequest(url="https://usim-free.example/", final_url="https://win-live.example/deposit",
                                        redirect_count=2, domains=["usim-free.example", "win-live.example"],
                                        pages=["라이브 카지노 슬롯 첫충 20%", "충전 신청 입금 계좌 환전 24시간"]))
    print("threat:", t.threat, t.probabilities, "hold" if t.hold else "", t.model, f"{t.latency_ms}ms")


if __name__ == "__main__":
    main()
