"""자동 수집: 공개 피싱 피드에서 주소를 받아 사람 손 없이 조사를 접수한다(사용자 결정 2026-10-24 A안).

- 출처는 서버 코드에 고정한 이름만(agent/feeds.py FEEDS). 받는 일은 브라우저 조사 워커와 떨어진 수집 컨테이너(feeder,
  격리망·검문 프록시로 GET 만)가 하고, API 는 자기가 만든 대기 번호(FeedFetch)의 결과만, feeder 와 API 만 가진 키의 서명이
  맞을 때 한 번 받는다. 조사 대상 페이지를 여는 브라우저 워커가 뚫려도 피드 결과를 꾸며 임의 주소를 자동 조사시키지 못한다
  (Codex 1회차 F1)
- 받은 글은 믿지 않는 값이다: 줄 수·길이 상한, 주소 형식 검사(netguard.parse_url), 같은 호스트는 며칠 안에 다시 넣지 않음,
  같은 키트 모양(공용 호스팅이면 호스팅 + 첫 경로, 아니면 등록 도메인)은 한 번에 몇 개까지, 한 번에 넣는 수 상한
- 사건은 끝나지 않은 자동 수집 사건이 한도(기본 1) 아래일 때만 하나씩 만든다: 조사 컨테이너가 하나여도 사람 신고가 길어야
  한 건만 기다린다. 하루(24시간) 상한. 사람 접수 한도(전체 대기)에는 세지 않는다
- 켜기·끄기는 사람 관리자만. 판정은 그대로 사람(검토관)이 한다
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import itertools
from collections import Counter
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .agent.feeds import FEEDS
from .decision.brands import SHARED_HOSTING, on_domain, site_of
from .netguard import BlockedURL, parse_url
from .store import Case, FeedFetch, FeedItem, IntakeState, Store, now

INTAKE_ACTOR = "system:intake"  # 사람 계정·토큰 이름 규칙과 겹치지 않는 내부 주체
INTERVAL_H = {"openphish": 12, "phishtank": 6}  # 출처 갱신 주기(OpenPhish 12시간, PhishTank 는 키 없이 하루 몇 번까지)
RETRY_FAILED = timedelta(hours=1)  # 받기에 실패한 출처를 다시 시도할 간격
FETCH_TTL = timedelta(minutes=10)  # 이 안에 결과가 오지 않은 받기는 만료
MAX_LINES = 3000
URL_MAX = 2048
SKIP_KEYS = ("format", "same_host", "seen_host", "kit", "over_cap")


def result_fields(res: dict) -> tuple[bool, str, bool, str]:
    """API 가 처리에 쓰는 결과 필드를 정해진 모양으로: (성공, 본문, 잘림, 실패 이유). 서명도 이 값 전체에 건다."""
    text = res.get("text") if isinstance(res.get("text"), str) else ""
    ok = res.get("ok") is True and isinstance(res.get("text"), str)
    return ok, text, res.get("truncated") is True, str(res.get("reason") or "")[:64]


def feed_mac(key: bytes, fetch_id: int, source: str, res: dict) -> str:
    """피드 결과 서명: 받기 번호·출처와 처리에 쓰는 결과 필드 전체(성공·잘림·실패 이유·본문 해시)에 묶는다. 다른 번호·출처로
    옮겨 쓰거나, 실패를 빈 성공으로·잘림 여부를 바꿔 쓸 수 없다(Codex 2회차 F1)."""
    ok, text, cut, reason = result_fields(res)
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    msg = f"safetrace.feed/2|{fetch_id}|{source}|{int(ok)}|{int(cut)}|{reason}|{digest}"
    return hmac.new(key, msg.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


def request_mac(key: bytes, fetch_id: int, source: str) -> str:
    """받기 요청 서명(API → feeder): feeder 는 API 가 만든 요청만 받는다(Codex 2회차 F2)."""
    return hmac.new(key, f"safetrace.feed-request/1|{fetch_id}|{source}".encode(), hashlib.sha256).hexdigest()


def parse(source: str, text: str, truncated: bool) -> list[str]:
    """피드 글에서 주소 목록. 본문을 상한에서 잘랐으면 마지막(잘린) 줄은 버린다."""
    if not isinstance(text, str):
        return []
    if truncated:
        text = text.rsplit("\n", 1)[0]
    if source == "openphish":
        return [ln.strip() for ln in itertools.islice(text.splitlines(), MAX_LINES) if ln.strip()]
    if source == "phishtank":  # phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
        out = []
        try:
            rows = csv.reader(io.StringIO(text))
            if next(rows, [])[:2] != ["phish_id", "url"]:
                return []
            for row in itertools.islice(rows, MAX_LINES):
                if len(row) < 8:
                    break
                if row[4] == "yes" and row[6] == "yes":
                    out.append(row[1].strip())
        except csv.Error:
            pass
        return out
    return []


def kit_key(url: str, host: str) -> str:
    """같은 키트로 볼 모양: 공용 호스팅이면 호스팅 도메인 + 첫 경로 조각(같은 키트를 하위 도메인만 바꿔 수십 개 올린다,
    매일 세트의 Meta 'Page Appeal' pages.dev 24~100개), 아니면 등록 도메인."""
    hosting = next((d for d in SHARED_HOSTING if on_domain(host, (d,))), None)
    if hosting:
        first = urlsplit(url).path.strip("/").split("/", 1)[0].lower()[:64]
        return f"{hosting}|{first}"
    return site_of(host)


def choose(urls: list[str], *, seen_hosts: set[str], allowed_ports: list[int], cap: int,
           kit_max: int) -> tuple[list[tuple[str, str]], Counter]:
    """대기열에 넣을 (주소, 호스트)와 뺀 이유별 수. 피드에 나온 순서(최신 먼저)를 지킨다."""
    picked: list[tuple[str, str]] = []
    skipped: Counter = Counter()
    kits: Counter = Counter()
    hosts: set[str] = set()
    for u in urls:
        if not isinstance(u, str) or not u or len(u) > URL_MAX:
            skipped["format"] += 1
            continue
        u = u.strip()
        try:
            parse_url(u, allowed_ports)  # 형식 검사. IP 검사는 에이전트가 접속 시점에 한다
            host = (urlsplit(u).hostname or "").lower().rstrip(".")
        except (BlockedURL, ValueError):
            skipped["format"] += 1
            continue
        if not host or not u.isprintable():
            skipped["format"] += 1
        elif host in hosts:
            skipped["same_host"] += 1
        elif host in seen_hosts:
            skipped["seen_host"] += 1
        elif kits[kit_key(u, host)] >= kit_max:
            skipped["kit"] += 1
        elif len(picked) >= cap:
            skipped["over_cap"] += 1
        else:
            kits[kit_key(u, host)] += 1
            hosts.add(host)
            picked.append((u, host[:253]))
    return picked, skipped


# ── 상태(DB) ─────────────────────────
def is_enabled(store: Store) -> bool:
    with store.session() as s:
        st = s.get(IntakeState, 1)
        return bool(st and st.enabled)


def set_enabled(store: Store, enabled: bool, actor: str) -> IntakeState:
    with store.session() as s, s.begin():
        st = s.get(IntakeState, 1)
        if st is None:
            st = IntakeState(id=1, enabled=enabled, updated_by=actor, updated_at=now())
            s.add(st)
        else:
            st.enabled, st.updated_by, st.updated_at = enabled, actor, now()
    return st


def _at(at: datetime | None) -> datetime:
    return at or now()


def _naive(dt: datetime) -> datetime:
    """UTC 기준 시각(SQLite 는 시간대 없이, PostgreSQL 은 시간대와 함께 돌려준다)."""
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def expire_fetches(store: Store, at: datetime | None = None) -> int:
    """결과가 오지 않은 오래된 받기를 만료한다(워커가 죽거나 이벤트를 잃은 경우). 반환: 만료한 수."""
    cut = _at(at) - FETCH_TTL
    with store.session() as s, s.begin():
        rows = list(s.scalars(select(FeedFetch).where(FeedFetch.state == "pending", FeedFetch.requested_at < cut)))
        for f in rows:
            f.state, f.done_at, f.reason = "expired", _at(at), "no_result"
    return len(rows)


def due_sources(store: Store, sources: list[str], at: datetime | None = None) -> list[str]:
    """받을 때가 된 출처: 대기 중인 받기가 없고, 마지막 받기가 주기(실패면 1시간)보다 오래됐다."""
    out = []
    t = _at(at)
    with store.session() as s:
        for src in sources:
            if src not in FEEDS or src not in INTERVAL_H:
                continue
            last = s.scalar(select(FeedFetch).where(FeedFetch.source == src).order_by(FeedFetch.id.desc()).limit(1))
            if last is None:
                out.append(src)
                continue
            if last.state == "pending":
                continue
            wait = RETRY_FAILED if last.state in ("failed", "expired") else timedelta(hours=INTERVAL_H[src])
            if _naive(t) - _naive(last.requested_at) >= wait:
                out.append(src)
    return out


def request_fetch(store: Store, source: str, at: datetime | None = None) -> FeedFetch | None:
    """받기 대기 줄을 만든다. 같은 출처에 대기 중인 줄이 있으면(동시 요청) None."""
    f = FeedFetch(source=source, state="pending", requested_at=_at(at))
    with store.session() as s:
        s.add(f)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            return None
    return f


def record_fetch(store: Store, fetch_id: object, res: object, *, seen_hosts: set[str], allowed_ports: list[int],
                 cap: int, kit_max: int, key: bytes | None, at: datetime | None = None) -> FeedFetch | None:
    """수집 컨테이너가 보낸 받기 결과. API 가 만든 대기 중인 번호이고, key 가 있으면 그 키의 서명(feed_mac)이 맞을 때만 한 번
    받아 고른 주소를 대기열에 넣는다. key=None 은 같은 프로세스에서 받은 결과(개발 모드)만 쓴다."""
    if type(fetch_id) is not int or not isinstance(res, dict):
        return None
    with store.session() as s, s.begin():
        f = s.get(FeedFetch, fetch_id, with_for_update=True)
        if f is None or f.state != "pending":
            return None
        ok, text, cut, reason = result_fields(res)
        if key is not None:
            mac = res.get("mac") if isinstance(res.get("mac"), str) else ""
            if not key or not hmac.compare_digest(mac, feed_mac(key, f.id, f.source, res)):
                return None  # 서명이 없거나 맞지 않는 결과는 받지 않는다(대기 줄은 그대로 두어 진짜 결과를 기다린다)
        f.done_at = _at(at)
        if not ok:
            f.state = "failed"
            f.reason = reason or "error"
            return f
        urls = parse(f.source, text[:1024 * 1024], cut)
        picked, skipped = choose(urls, seen_hosts=seen_hosts, allowed_ports=allowed_ports, cap=cap, kit_max=kit_max)
        s.add_all(FeedItem(fetch_id=f.id, source=f.source, url=u, host=h, created_at=_at(at)) for u, h in picked)
        f.state, f.got, f.picked = "done", len(urls), len(picked)
        f.skipped = {k: skipped[k] for k in SKIP_KEYS if skipped[k]}
    return f


def recent_hosts(store: Store, days: int, at: datetime | None = None) -> set[str]:
    """최근 며칠 안에 대기열에 넣었거나 사건으로 접수한 호스트(사람 신고 포함)."""
    since = _at(at) - timedelta(days=days)
    with store.session() as s:
        hosts = set(s.scalars(select(FeedItem.host).where(FeedItem.created_at >= since)))
        for u in s.scalars(select(Case.url).where(Case.created_at >= since)):
            try:
                h = (urlsplit(u).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
            if h:
                hosts.add(h)
    return hosts


def status(store: Store, sources: list[str], at: datetime | None = None) -> dict:
    """콘솔 표시용: 켜짐, 출처별 마지막 받기, 대기열 수, 최근 24시간 만든 사건 수(값·주소는 없다)."""
    t = _at(at)
    with store.session() as s:
        st = s.get(IntakeState, 1)
        last = {}
        for src in sources:
            f = s.scalar(select(FeedFetch).where(FeedFetch.source == src).order_by(FeedFetch.id.desc()).limit(1))
            last[src] = None if f is None else {
                "state": f.state, "requested_at": f.requested_at.isoformat(),
                "done_at": f.done_at.isoformat() if f.done_at else None, "got": f.got, "picked": f.picked,
                "skipped": f.skipped or {}, "reason": f.reason}
        queued = len(list(s.scalars(select(FeedItem.id).where(FeedItem.state == "queued"))))
        day = len(list(s.scalars(select(Case.id).where(Case.created_by == INTAKE_ACTOR,
                                                       Case.created_at >= t - timedelta(hours=24)))))
        pending = len(list(s.scalars(select(Case.id).where(Case.created_by == INTAKE_ACTOR,
                                                           Case.status.in_(("QUEUED", "RUNNING"))))))
    return {"enabled": bool(st and st.enabled), "updated_by": st.updated_by if st else None,
            "updated_at": st.updated_at.isoformat() if st else None, "sources": last, "queued": queued,
            "pending": pending, "created_24h": day}
