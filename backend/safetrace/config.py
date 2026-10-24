"""환경 설정. 모든 값은 ST_ 접두사 환경변수 또는 .env 로 주입한다.

시크릿은 서비스별로 필요한 것만 주입한다.
- Jev/OpenRouter API 키: 판단 서비스(decision)에만
- 증거 HMAC 키: 서명 서비스(signer)와 API(검증)에만. 에이전트 워커·DB·증거 저장소에는 두지 않는다
- 에이전트 워커: DB 접속 정보·서명 키 없음. 진행 상황은 이벤트로만 내보내고, 기록은 서명 서비스에 맡긴다
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
    # 서명 서비스. 비우면 같은 프로세스에서 서명한다(개발 모드)
    signer_url: str | None = None  # 예: http://signer:8200
    signer_agent_token: SecretStr = SecretStr("")  # 에이전트 → 서명 서비스: 기록 추가만
    signer_api_token: SecretStr = SecretStr("")  # API → 서명 서비스: 체인 열기·닫기·head 조회
    signer_state_path: Path = Path("./var/signer.db")  # 서명 서비스가 사건별 head 를 두는 곳

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
    # 연관 후보 하위 조사(원래 주소가 확신 있는 정상이 아닐 때만): 사건당 개수와 후보 하나의 단계·시간 한도
    candidate_max: int = Field(3, ge=0, le=5)
    candidate_max_steps: int = Field(4, ge=1, le=15)
    candidate_max_seconds: int = Field(40, ge=10, le=120)
    max_seconds: int = 120
    max_same_state: int = 2
    max_candidates: int = 50
    nav_timeout_ms: int = 15000
    egress_proxy: str | None = None  # 예: http://egress:3128
    resolver_url: str | None = None  # 격리망에서 1차 IP 확인용 DNS 조회. 예: http://egress:3129
    record_video: bool = True
    live_max_fps: int = 60  # 콘솔 실시간 화면(보는 사람이 있을 때만 전송). 브라우저 화면 전송은 움직일 때 초당 약 56장
    ffmpeg_path: str = ""  # 비우면 PATH·Playwright 가 받아 둔 ffmpeg 를 찾는다. 없으면 Playwright 내장 녹화
    ocr_enabled: bool = True
    # 관찰 한 번에 이미지 버튼 OCR 에 쓰는 최대 시간(초). 이미지가 많은 첫 화면이 조사 시간을 다 쓰지 않게 한다
    ocr_observe_max_seconds: int = 30
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
    # 접속 주소별 로그인 실패 한도(창 안). 사무실처럼 여러 담당자가 한 주소를 같이 쓰는 경우를 생각해 계정별(5회)보다 넉넉히
    login_ip_max_failed: int = Field(30, ge=1)
    login_ip_window_s: int = Field(900, ge=60)
    # X-Forwarded-For 를 믿는 프록시의 호스트 이름(Compose: ["web"]). 비우면 접속한 쪽 주소만 쓴다
    trusted_proxies: list[str] = Field(default_factory=list)
    # 접수 한도: 끝나지 않은(대기·조사 중) 사건 수. 주체(계정·자동화 토큰)별, 전체
    case_max_pending_per_principal: int = Field(20, ge=1)
    case_max_pending_total: int = Field(200, ge=1)
    # 연관 후보 자동 사건(related.py 선별 조건 통과만): 켜기, 부모당 개수, 끝나지 않은 자동 사건 전체, 같은 도착 호스트 중복 기간
    related_auto: bool = True
    related_auto_per_case: int = Field(3, ge=0, le=3)
    related_auto_max_pending: int = Field(10, ge=0, le=50)
    related_auto_dedup_days: int = Field(7, ge=1, le=30)
    # 조치 추적 재확인(actions.py): 켜기, 같은 사건을 다시 볼 간격, 한 바퀴에 맡기는 수, 바퀴 간격(초)
    recheck_enabled: bool = True
    recheck_interval_hours: int = Field(24, ge=1, le=24 * 30)
    recheck_batch: int = Field(10, ge=1, le=100)
    recheck_tick_s: int = Field(300, ge=10, le=86400)
    # 자동 수집(intake.py): 켜기·끄기는 콘솔(관리자)이 DB 에 둔다. 출처, 바퀴 간격(초), 끝나지 않은 자동 수집 사건 한도
    # (조사 컨테이너가 하나여도 사람 신고가 길어야 이만큼만 기다린다), 24시간 사건 상한, 한 번 받기에서 대기열에 넣는 수,
    # 같은 키트 모양 수, 같은 호스트를 다시 넣지 않는 기간
    intake_sources: list[str] = Field(default_factory=lambda: ["openphish", "phishtank"])
    # 피드 결과 서명 키: 수집 컨테이너(feeder)와 API 에만 둔다. 브라우저 조사 워커에는 넣지 않는다
    feed_key: SecretStr = SecretStr("")
    intake_tick_s: int = Field(15, ge=5, le=3600)
    intake_max_pending: int = Field(1, ge=0, le=10)
    intake_daily_max: int = Field(120, ge=0, le=2000)
    intake_round_max: int = Field(30, ge=1, le=300)
    intake_kit_max: int = Field(2, ge=1, le=50)
    intake_dedup_days: int = Field(7, ge=1, le=30)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
