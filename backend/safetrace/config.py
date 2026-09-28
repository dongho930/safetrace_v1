"""환경 설정. 모든 값은 ST_ 접두사 환경변수 또는 .env 로 주입한다.

시크릿은 서비스별로 필요한 것만 주입한다.
- Jev/OpenRouter API 키: 판단 서비스(decision)에만
- 증거 HMAC 키: 에이전트 워커(서명)와 API(검증)에만. DB·증거 저장소에는 두지 않는다
- 에이전트 워커: DB 접속 정보 없음. 진행 상황은 이벤트로만 내보낸다
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ST_", env_file=".env", extra="ignore")

    # 저장소
    database_url: str = "sqlite:///./var/safetrace.db"
    evidence_dir: Path = Path("./var/evidence")
    redis_url: str | None = None  # 없으면 API 프로세스 안에서 에이전트를 실행(개발 모드)

    # 증거 서명 키: 저장소 권한과 분리해 보관한다
    evidence_hmac_key: SecretStr = SecretStr("")
    evidence_key_id: str = "k1"

    # 판단 서비스
    decision_url: str = "http://127.0.0.1:8100"
    decision_token: SecretStr = SecretStr("")  # 에이전트 → 판단 서비스 내부 인증
    decider_chain: list[str] = Field(default_factory=lambda: ["jev_typesafe", "jev_openrouter", "rules"])
    typesafe_api_key: SecretStr = SecretStr("")
    typesafe_base_url: str = "https://api.typesafe.ai"
    jev_model: str = "jev-1.13.0"  # 버전 고정
    openrouter_api_key: SecretStr = SecretStr("")
    openrouter_base_url: str = "https://openrouter.ai/api"
    openrouter_jev_model: str = "typesafe/jev-1.13"
    decision_timeout_s: float = 8.0
    action_min_prob: float = 0.45
    threat_min_prob: float = 0.6

    # 에이전트 예산
    max_steps: int = 15
    max_seconds: int = 120
    max_same_state: int = 2
    max_candidates: int = 50
    nav_timeout_ms: int = 15000
    egress_proxy: str | None = None  # 예: http://egress:3128
    resolver_url: str | None = None  # 격리망에서 1차 IP 확인용 DNS 조회. 예: http://egress:3129
    record_video: bool = True
    ocr_enabled: bool = True
    # 브라우저: 봇에게 다른 화면을 보여주거나 막는 사이트(클로킹)가 많아, 전체 Chromium 의 새 헤드리스 모드와
    # 실행 중인 버전에 맞춘 일반 User-Agent 를 쓴다. 비우면 Playwright 기본(headless shell, HeadlessChrome UA).
    # 관찰·마지막 화면은 페이지 전체를 캡처한다(숨은 계좌·양식이 아래쪽에 있는 경우가 많음). 너무 긴 페이지는 이 높이에서 자른다
    screenshot_max_height: int = 6000
    browser_channel: str = "chromium"
    browser_user_agent: str = "auto"  # auto | 직접 지정 문자열 | 빈 문자열(기본값 사용)

    # SSRF: 허용 포트, 시험용 허용 목록(host:port). 운영에서는 비워 둔다.
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    test_allowlist: list[str] = Field(default_factory=list)

    # 외부 조회
    safebrowsing_api_key: SecretStr = SecretStr("")

    # API 인증: "토큰:역할" 목록. 역할 = viewer | investigator | reviewer | admin
    api_tokens: list[str] = Field(default_factory=list)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
