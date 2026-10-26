"""AI 브라우저 에이전트 루프: 관찰 → Jev 행동 선택 → 안전 게이트 → 실행·기록.

에이전트는 DB에 접근하지 않는다. 증거는 서명해 파일로 남기고, 진행 상황은 emit() 이벤트로만 내보낸다.
텍스트 입력 기능은 아예 구현하지 않았다(fill/type/press 호출 없음. Escape 키만 팝업 닫기에 사용).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import logging
import math
import re
import secrets
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from PIL import Image
from playwright.async_api import Browser, BrowserContext, Page, Route, async_playwright
from playwright.async_api import Error as PWError
from playwright.async_api import TimeoutError as PWTimeout

from ..config import Settings
from ..decision.client import Decider, DecisionUnavailable
from ..decision.schema import ActionKind, Candidate, PageState, ThreatRequest, action_options
from ..evidence import EvidenceWriter
from ..masking import mask_pii
from ..proxy.egress import EGRESS_HEADER
from . import netfilter
from .candidates import TEXT_MAX, platform_link
from .candidates import select as select_candidates
from .gate import Budget, ElementInfo, SafetyGate, classify_forbidden
from .observe import CLOSE_POPUP_JS, COLLECT_JS, READ_ONE_JS, RECTS_JS
from .recorder import ScreencastRecorder, find_ffmpeg
from .ocr import get_ocr

log = logging.getLogger("safetrace.agent")

# 최초 접속 실패 사유. Chromium 의 net::ERR_* 코드만 남긴다(오류 문구 전체는 URL 등이 섞일 수 있어 남기지 않음).
_NET_ERR = re.compile(r"net::(ERR_[A-Z0-9_]+)")
_NET_CATEGORY = {
    "ERR_NAME_NOT_RESOLVED": "dns_failure",
    "ERR_NAME_RESOLUTION_FAILED": "dns_failure",
    "ERR_CONNECTION_REFUSED": "connection_refused",
    "ERR_CONNECTION_RESET": "connection_dropped",
    "ERR_CONNECTION_CLOSED": "connection_dropped",
    "ERR_EMPTY_RESPONSE": "connection_dropped",
    "ERR_CONNECTION_TIMED_OUT": "timeout",
    "ERR_TIMED_OUT": "timeout",
    "ERR_TUNNEL_CONNECTION_FAILED": "egress_refused",   # 검문 프록시가 거부했거나 상대에 연결 못 함
    "ERR_PROXY_CONNECTION_FAILED": "egress_unavailable",
    "ERR_BLOCKED_BY_CLIENT": "blocked_by_policy",       # netguard 가 요청을 막음
    "ERR_ADDRESS_UNREACHABLE": "network_unreachable",
    "ERR_INTERNET_DISCONNECTED": "network_unreachable",
}

# 잠시 뒤 스스로 목적지로 넘어가는 대기 화면(단축 URL 서비스). 실제로 관찰한 문구만 넣는다:
# goo.su "Redirecting... Please wait", lrl.kr "곧 원하시는 페이지로 이동됩니다 … 7 초 후 이동합니다"
_AUTO_REDIRECT = re.compile(r"Redirecting\.\.\.|Please wait|원하시는 페이지로 이동|초 후 이동합니다")
_AUTO_REDIRECT_WAIT = 10.0  # 대기 화면에서 이동을 기다리는 최대 시간(초)
# 이동 요청 검사(이름 해석)의 상한(초). 넘으면 열 수 없는 곳으로 막는다(ssrf:dns_timeout).
# 이름 해석이 느린 회선에서는 검사가 끝나기 전에 관찰·판단을 마쳐 목적지를 놓쳤다(CI 에서 가끔 실패하던 원인)
_NAV_CHECK_TIMEOUT = 4.0


def is_auto_redirect_page(text: str) -> bool:
    return bool(_AUTO_REDIRECT.search(text[:2000]))


_EID = re.compile(r"e\d{1,6}")  # 관찰이 요소에 붙이는 ID 형식
# 상자 하나를 찾는 최대 시간(있는 요소는 바로 찾는다. 사라졌으면 이만큼 기다리고 포기, 상자들은 동시에 잰다).
# 새 페이지의 첫 측정은 Playwright 가 스크립트를 주입해 2~3배 느리다(CPU 8배 감속 시 약 150ms). 150ms 일 때 CI 에서 상자가 통째로 빠졌다.
_BOX_TIMEOUT_MS = 500


async def measure_rects(page: Page, attr: str, ids: list[str]) -> tuple[dict | None, list[dict | None]]:
    """관찰 화면 위에 그릴 요소 상자를 잰다. 페이지 JS(바꿔치기할 수 있는 querySelector·getBoundingClientRect·scrollY)를
    쓰지 않고 Playwright 의 bounding_box(분리된 실행 영역에서 찾고 브라우저 프로토콜로 잼)를 쓴다.
    스크롤 위치도 페이지가 옮길 수 있는 html 상자 대신 브라우저 프로토콜(Page.getLayoutMetrics)에서 읽는다.
    결과: (원점 {"x": -스크롤X, "y": -스크롤Y}, 요소마다 창 기준 상자). 표시 속성이 둘 이상에 붙어 있으면 None."""
    async def bb(sel: str | None) -> dict | None:
        if sel is None:
            return None
        try:
            return await page.locator(sel).bounding_box(timeout=_BOX_TIMEOUT_MS)
        except (PWError, PWTimeout):
            return None

    async def origin() -> dict | None:
        try:
            cdp = await page.context.new_cdp_session(page)
            try:
                v = (await cdp.send("Page.getLayoutMetrics"))["cssVisualViewport"]
            finally:
                await cdp.detach()
            return {"x": -float(v["pageX"]), "y": -float(v["pageY"])}
        except (PWError, PWTimeout, KeyError, TypeError, ValueError):
            return None

    sels = [f'[{attr}="{i}"]' if _EID.fullmatch(i) else None for i in ids]
    root, *rects = await asyncio.gather(origin(), *(bb(x) for x in sels))
    return root, rects


# 스크롤이 잠긴 문서(html 이 스크롤을 막고 body 가 스크롤): 페이지 전체 캡처가 첫 화면만 그리고 나머지를 배경색으로 채우는데,
# 상자는 요소의 실제 배치(아래쪽)에 그려졌다(kc-telegram 등 중국 도박 복제 사이트). 캡처하는 동안만 잠금을 풀어 문서를
# 내용 높이로 늘리고 끝나면 되돌린다. 페이지 JS 가 막거나 응답하지 않으면 펼치지 못할 뿐 지금과 같은 결과다.
# 잠김 판정: 화면(viewport)이 스크롤하지 못하거나(html 의 overflow, html 이 visible 이면 body 값이 화면으로 넘어감)
# 문서는 화면에 들어가는데 body 만 길 때. 문서 높이만 보면 body 여백 몇 px 때문에 스크롤하는 문서로 잘못 본다.
_EXPAND_JS = """(mark) => {
  const de = document.documentElement, b = document.body, vh = window.innerHeight;
  if (!b || b.scrollHeight <= vh + 2) return null;
  const ho = getComputedStyle(de).overflowY, vo = ho === 'visible' ? getComputedStyle(b).overflowY : ho;
  if (!(vo === 'hidden' || vo === 'clip' || de.scrollHeight <= vh + 2)) return null;
  const saved = [de.scrollTop, b.scrollTop];
  const st = document.createElement('style');
  st.setAttribute(mark, '');
  st.textContent = 'html, body { height: auto !important; min-height: 0 !important; max-height: none !important; overflow: visible !important; }';
  (document.head || de).appendChild(st);
  return saved;
}"""
_RESTORE_JS = """([mark, saved]) => {
  for (const s of document.querySelectorAll('style[' + mark + ']')) s.remove();
  if (saved) { document.documentElement.scrollTop = saved[0]; if (document.body) document.body.scrollTop = saved[1]; }
}"""
_LAYOUT_TIMEOUT_S = 2.0
_TWO_FRAMES_JS = "() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))"


@contextlib.asynccontextmanager
async def full_layout(page: Page, mark: str):
    """스크롤이 잠긴 문서를 캡처하는 동안만 펼친다. 펼쳤으면 True(관찰 기록에 capture: "expanded" 로 남긴다).
    mark 는 넣은 style 을 찾아 지우는 속성 이름. 페이지가 돌려준 값은 믿지 않고 모양만 확인한다."""
    timed_out = False
    try:
        saved = await asyncio.wait_for(page.evaluate(_EXPAND_JS, mark), _LAYOUT_TIMEOUT_S)
    except asyncio.TimeoutError:
        saved, timed_out = None, True
    except PWError:
        saved = None
    ok = isinstance(saved, list) and len(saved) == 2 and all(isinstance(v, (int, float)) for v in saved)
    if ok:  # 펼친 배치가 화면에 한 번 그려진 뒤 재고 찍는다(바로 찍으면 fixed 요소가 이전 자리에 그려질 때가 있다)
        try:
            await asyncio.wait_for(page.evaluate(_TWO_FRAMES_JS), 1.0)
        except (PWError, asyncio.TimeoutError):
            pass
    try:
        yield ok
    finally:
        # 펼쳤거나, 시간 초과로 나중에 펼쳐졌을 수 있으면 넣은 style 을 지운다(잠기지 않은 보통 페이지는 왕복 없음)
        if ok or timed_out:
            try:
                await asyncio.wait_for(page.evaluate(_RESTORE_JS, [mark, saved if ok else None]), _LAYOUT_TIMEOUT_S)
            except (PWError, asyncio.TimeoutError):
                pass


_PNG_SIG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])  # PNG 파일 서명


def png_size(path: Path) -> tuple[int, int] | None:
    """PNG 머리에서 (폭, 높이). 상자 좌표는 실제로 저장한 캡처 크기에 맞춘다."""
    try:
        with path.open("rb") as f:
            head = f.read(24)
    except OSError:
        return None
    if len(head) < 24 or head[:8] != _PNG_SIG or head[12:16] != b"IHDR":
        return None
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def boxes_from(root: dict | None, rects: list[dict | None], size: tuple[int, int] | None,
               cand_ids: list[str], n_forbidden: int) -> dict | None:
    """창 기준 상자를 캡처 이미지 픽셀로: 창 좌표 + 스크롤(= 창 좌표 - 원점). Chromium 전체 캡처는
    position: fixed 요소도 캡처 순간 자리에 찍으므로 같은 식이 맞는다(시험: test_boxes_match_full_page_capture).
    캡처 범위로 자르고, 범위 밖·너무 작으면 None. 결과: {"size": [폭, 높이], "cand": {ID: [x,y,w,h]}, "forbidden": [...]}"""
    if root is None or size is None or len(rects) != len(cand_ids) + n_forbidden:
        return None
    w, h = size

    def one(r: dict | None) -> list[int] | None:
        if r is None:
            return None
        x0, y0 = r["x"] - root["x"], r["y"] - root["y"]
        x1, y1 = min(x0 + r["width"], w), min(y0 + r["height"], h)
        x, y = max(0.0, x0), max(0.0, y0)
        if x1 - x < 2 or y1 - y < 2:
            return None
        bx = [round(x), round(y), round(x1 - x), round(y1 - y)]
        bx[2], bx[3] = min(bx[2], w - bx[0]), min(bx[3], h - bx[1])
        return bx if bx[2] > 0 and bx[3] > 0 else None

    out = [one(r) for r in rects]
    cand = {i: b for i, b in zip(cand_ids, out[: len(cand_ids)]) if b}
    forbidden = out[len(cand_ids):]
    if not cand and not any(forbidden):
        return None
    return {"size": [w, h], "cand": cand, "forbidden": forbidden}


def classify_goto_error(e: Exception) -> dict:
    """최초 접속 실패를 '사이트가 내려감'과 '우리를 막음'을 구분할 수 있는 분류로 바꾼다."""
    if isinstance(e, PWTimeout):
        return {"error": type(e).__name__, "net_error": None, "category": "timeout"}
    m = _NET_ERR.search(str(e))
    code = m.group(1) if m else None
    if code is None:
        category = "other"
    elif code.startswith(("ERR_SSL_", "ERR_CERT_")):
        category = "tls_error"
    else:
        category = _NET_CATEGORY.get(code, "other")
    return {"error": type(e).__name__, "net_error": code, "category": category}


Emit = Callable[[dict], None]
_ALLOWED_METHODS = {"GET", "HEAD"}
# 스크롤한 뒤 두 프레임을 기다려 다시 그려진 화면을 찍는다
_SCROLL_TO_JS = "(y) => new Promise((r) => { window.scrollTo(0, y); requestAnimationFrame(() => requestAnimationFrame(r)); })"
_OCR_SHOT_TIMEOUT_MS = 3000  # 이미지 버튼 한 개를 찍는 최대 시간
_PW_DEFAULT_TIMEOUT_MS = 30000  # Playwright 기본 제한(이 모듈은 따로 바꾸지 않는다)
# 시간 예산은 단계 사이에서 확인한다. 페이지 스크립트가 메인 스레드를 붙잡으면 evaluate 등이 돌아오지 않아 그 확인에
# 닿지 못하므로, 탐색 전체에 예산 + 여유의 강제 기한을 둔다. 정리(녹화 중지·브라우저 닫기)에도 제한을 둔다
_HARD_GRACE_S = 15.0
_CLEANUP_TIMEOUT_S = 10.0
_PAGE_LINKS_MAX = 200  # 관찰 한 번에 받는 링크(COLLECT_JS 와 같은 상한)


def _page_links(raw) -> list[dict]:
    """COLLECT_JS 가 모은 링크(페이지가 정한 값)를 정해진 모양으로만 받는다: http·https 절대 주소 2048자 이하,
    앵커 글자는 개인정보를 가린 뒤 80자. 보이는지 여부는 남기지만 고르는 데는 쓰지 않는다.
    클릭 후보에서 막는 링크(결제·다운로드·로그인 등, gate.classify_forbidden)는 받지 않는다: 연관 후보로 골라 하위 조사가
    그 주소를 열면 클릭 금지를 우회하게 된다(Codex 지적)."""
    out = []
    for x in raw if isinstance(raw, list) else []:
        if len(out) >= _PAGE_LINKS_MAX:
            break
        if not isinstance(x, dict) or not isinstance(x.get("href"), str):
            continue
        href = x["href"]
        if len(href) > 2048 or not href.startswith(("http://", "https://")):
            continue
        text = x.get("text") if isinstance(x.get("text"), str) else ""
        info = ElementInfo.from_js({"tag": "a", "href": href, "text": text, "hasDownload": x.get("hasDownload") is True,
                                    "inForm": x.get("inForm") is True})
        if classify_forbidden(info):
            continue
        if x.get("imgOnly") is True and not text.strip():
            # 글자 없는 이미지 링크는 무엇인지 모른다(이미지 '결제' 버튼일 수 있다). 클릭 후보로 OCR 을 거쳐 통과한 것만
            # _note_links 가 클릭 후보 쪽에서 받는다
            continue
        out.append({"url": href, "text": mask_pii(text[:200])[:TEXT_MAX], "visible": x.get("visible") is True})
    return out


def _is_main_frame(req) -> bool:
    """페이지(새 창 포함) 자체의 이동인지. 광고 iframe 의 이동은 판단 근거로 쓰지 않는다."""
    try:
        return req.frame.parent_frame is None
    except PWError:  # 서비스 워커 요청 등 프레임이 없는 경우
        return False


def browser_user_agent(setting: str, version: str) -> str:
    """'auto' 면 실행 중인 Chromium 주 버전에 맞춘 일반 Chrome User-Agent(운영체제 표기는 실제 OS 따름)."""
    if setting != "auto":
        return setting
    major = version.split(".")[0]
    platform = {"win32": "Windows NT 10.0; Win64; x64", "darwin": "Macintosh; Intel Mac OS X 10_15_7"}.get(
        sys.platform, "X11; Linux x86_64")
    return f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"


_CHROMIUM_ARGS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-features=InterestFeedContentSuggestions,MediaRouter,DialMediaRouteProvider",
    "--disable-background-networking",
    "--no-first-run",
    "--disable-sync",
]


@dataclass
class RunResult:
    status: str  # COMPLETED | REVIEW_REQUIRED | FAILED | UNREACHABLE | BLOCKED
    finish_reason: str
    final_url: str = ""
    threat: dict | None = None
    steps: int = 0
    nav_chain: list[str] = field(default_factory=list)
    candidates_found: list[dict] = field(default_factory=list)  # 연관 후보 {url, host, source, score, text}(candidates.select)
    # 관찰한 화면의 링크 {url, text}(외부 링크 후보의 원천, 사건 전체 100개). text 는 개인정보를 가린 앵커 글자
    links_found: list[dict] = field(default_factory=list)
    blocked_requests: int = 0
    forbidden_seen: list[str] = field(default_factory=list)
    blocked_destinations: list[dict] = field(default_factory=list)  # 열리지 않은 이동 목적지 {host, reason}
    network_filtered: bool = False  # 접속 불가의 원인이 회선의 도메인 이름 차단(통신사·기관)으로 보임


@dataclass
class _Observation:
    state: PageState
    infos: dict[str, ElementInfo]
    forbidden: list[str]
    evidence_seq: int
    state_key: str
    links: list[dict] = field(default_factory=list)  # 화면의 모든 링크 {url, text}(판단 모델에는 보내지 않음)


_FEW_CONTROLS = 3  # 누를 것이 이만큼 이하인 화면만 늦게 나타나는 버튼을 기다린다
_CONTROLS_WAIT = 3.0  # 최대로 기다리는 시간(초)
# 누를 수 있어 보이는 요소 수. 탐색(기다릴지)에만 쓰고 안전 판단에는 쓰지 않는다
_COUNT_CONTROLS_JS = """() => {
  let n = 0;
  for (const el of document.querySelectorAll('a[href],button,[role=button],input[type=button],input[type=submit],[onclick]')) {
    const r = el.getBoundingClientRect();
    if (r.width > 2 && r.height > 2) n++;
    if (n > 500) break;
  }
  return n;
}"""


async def _count_controls(page: Page) -> int | None:
    try:
        n = await asyncio.wait_for(page.evaluate(_COUNT_CONTROLS_JS), 1.0)
    except (PWError, PWTimeout, asyncio.TimeoutError):
        return None
    return n if isinstance(n, int) and not isinstance(n, bool) else None


async def _bounded(aw, what: str):
    """정리 작업이 응답 없는 페이지에 묶이지 않게 제한 시간을 둔다. 실패해도 조사 결과는 그대로 둔다."""
    try:
        return await asyncio.wait_for(aw, _CLEANUP_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001  정리 실패는 기록만
        log.warning("%s failed: %s", what, type(e).__name__)
        return None


class AgentRun:
    def __init__(self, url: str, settings: Settings, decider: Decider, writer: EvidenceWriter, emit: Emit,
                 resolver=None, live=None, sub: int = 0):
        """sub: 연관 후보 하위 조사 번호(1부터). 0 이면 원래 조사. 하위 조사는 같은 증거 체인에 쓰고,
        기록·이벤트에 sub 를 붙이고 파일 이름 앞에 c<번호>_ 를 붙여 원래 조사와 섞이지 않게 한다."""
        self.start_url = url
        self.sub = sub
        self._tag = f"c{sub}_" if sub else ""
        if sub:
            emit = (lambda e, _emit=emit: _emit({**e, "sub": sub}))
        self.s = settings
        self.decider = decider
        self.ev = writer
        self.emit = emit
        self.gate = SafetyGate(settings.allowed_ports, settings.test_allowlist, resolver)
        self.budget = Budget(settings.max_steps, settings.max_seconds, settings.max_same_state)
        self.attr = "data-st-" + secrets.token_hex(4)
        self.result = RunResult(status="RUNNING", finish_reason="")
        self.history: list[str] = []
        self.rec: ScreencastRecorder | None = None
        self.live = live  # LiveSink(선택): 콘솔 실시간 화면
        self.page_summaries: list[str] = []
        self.page_urls: list[str] = []  # page_summaries 와 같은 순서로 그 화면을 연 주소(브라우저 값)
        self.page_titles: list[str] = []  # 같은 순서로 그 화면의 제목과 금지 요소(코드 규칙이 한 화면 근거끼리만 묶게)
        self.page_forbidden: list[list[str]] = []
        self.summary_evidence: list[int] = []
        self._shot = 0
        self._host_ok: dict[str, tuple[float, bool, str]] = {}
        self._egress_refused: set[str] = set()  # 검문 프록시가 거부 응답을 돌려준 주소(그 응답 화면은 막다른 곳)
        self._dead_links: set[tuple[str, str]] = set()  # 막다른 곳으로 이어진 (페이지 주소, 버튼 글자)
        self._waited: set[str] = set()  # 자동 이동을 기다려 본 대기 화면 주소(한 번만 기다린다)
        self._waited_controls: set[str] = set()  # 늦게 나타나는 버튼을 기다려 본 주소(한 번만 기다린다)
        self._nav_checks = 0  # 검사 중인 주 화면 이동 요청 수

    def _act(self, code: str, n: int | None = None):
        """콘솔 실시간 화면에 '지금 하는 일'을 알린다(live.ACTIVITIES, 보기용이며 증거 기록이 아니다)."""
        if self.live:
            self.live.activity(code, n)

    # ── 기록 ──────────────────────────────────────────
    def _record(self, kind: str, data: dict, files: list[str] | None = None) -> int:
        if self.sub:
            data = {**data, "sub": self.sub}
        rec = self.ev.append(kind, data, files)
        self.emit({"type": "evidence", "seq": rec["seq"], "kind": kind, "data": data,
                   "files": list(rec["files"].keys()), "hash": rec["hash"]})
        return rec["seq"]

    @contextlib.asynccontextmanager
    async def _capture_layout(self, page: Page):
        """페이지 전체 캡처 준비(full_layout). 펼친 모습이 녹화·실시간 화면에 찍히지 않게 그동안 녹화를 멈춘다."""
        self._act("capture")
        if self.rec:
            self.rec.pause()
        try:
            async with full_layout(page, f"{self.attr}-cap") as expanded:
                yield expanded
        finally:
            if self.rec:
                self.rec.resume()

    async def _screenshot(self, page: Page, label: str, full: bool = False) -> str | None:
        """full=True 면 페이지 전체(세로 screenshot_max_height 까지), 아니면 보이는 창만."""
        self._shot += 1
        name = f"{self._tag}s{self._shot:03d}_{label}.png"
        try:
            if full:
                self._act("capture")
                if self.rec:
                    self.rec.pause()  # 페이지 전체 캡처 중에는 창 크기가 잠시 바뀌어 녹화 프레임이 어긋난다
                try:  # 크기 조회(페이지가 망칠 수 있음)부터 감싸 멈춤이 남지 않게(남으면 녹화가 조사 끝까지 멈춘다)
                    vw, h = await page.evaluate(
                        "() => [window.innerWidth, Math.max(document.documentElement.scrollHeight,"
                        " document.body ? document.body.scrollHeight : 0)]")
                    clip = {"x": 0, "y": 0, "width": int(vw), "height": max(1, min(int(h), self.s.screenshot_max_height))}
                    png = await page.screenshot(timeout=15000, animations="disabled", full_page=True, clip=clip)
                finally:
                    if self.rec:
                        self.rec.resume()
            else:
                png = await page.screenshot(timeout=8000, animations="disabled")
        except (PWError, PWTimeout, TypeError, ValueError):
            return None
        self.ev.file_path(name).write_bytes(png)
        return name

    # ── 네트워크 통제(1차): 모든 요청을 가로채 검사 ─────────────
    def _host_allowed(self, url: str) -> tuple[bool, str]:
        parts = urlsplit(url)
        key = f"{parts.scheme}://{parts.netloc}"
        now = time.monotonic()
        cached = self._host_ok.get(key)
        if cached and now - cached[0] < 10:
            return cached[1], cached[2]
        res = self.gate.check_nav(url)
        self._host_ok[key] = (now, res.allowed, res.reason)
        return res.allowed, res.reason

    async def _on_route(self, route: Route):
        req = route.request
        url = req.url
        scheme = urlsplit(url).scheme.lower()
        if scheme in {"data", "blob", "about"}:
            await route.continue_()
            return
        reason = None
        main_nav = req.is_navigation_request() and _is_main_frame(req)
        if req.method.upper() not in _ALLOWED_METHODS:
            reason = f"method:{req.method.upper()}"
        else:
            self._nav_checks += main_nav
            try:
                ok, why = await asyncio.wait_for(asyncio.to_thread(self._host_allowed, url), _NAV_CHECK_TIMEOUT)
            except TimeoutError:
                ok, why = False, "ssrf:dns_timeout"
            finally:
                self._nav_checks -= main_nav
            if not ok:
                reason = why
        if reason:
            self.result.blocked_requests += 1
            if reason.startswith("ssrf:") and main_nav:
                self._note_blocked_destination(url, reason)
            if req.is_navigation_request() or reason.startswith("method"):
                self._record("blocked_request", {"url": url[:500], "reason": reason,
                                                 "navigation": req.is_navigation_request()})
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    def _note_blocked_destination(self, url: str, reason: str):
        """열리지 않은 이동 목적지를 위협 판단 입력으로 모은다. 도착지 화면이 없어도 도메인 이름은 근거가 된다
        (예: 단축 URL → name.n-payost.shop 이 이미 사라짐). 열린 페이지만 담는 nav_chain 에는 남지 않는다."""
        host = urlsplit(url).hostname
        seen = self.result.blocked_destinations
        if host and len(seen) < 20 and all(b["host"] != host for b in seen):
            seen.append({"host": host[:253], "reason": reason[:64]})

    def _on_request_failed(self, req):
        # 검문 프록시가 거부했거나 상대에 연결하지 못한 이동(서버 리다이렉트로 간 곳 포함).
        # 우리가 막은 요청(ERR_BLOCKED_BY_CLIENT)은 _on_route 가 이미 기록했고, ERR_ABORTED 는 다른 이동에 밀려 취소된 것이다
        try:
            if not (req.is_navigation_request() and _is_main_frame(req)):
                return
            code = _NET_ERR.search(req.failure or "")
        except PWError:
            return
        if code and code.group(1) not in ("ERR_BLOCKED_BY_CLIENT", "ERR_ABORTED"):
            self._note_blocked_destination(req.url, "net:" + code.group(1))

    def _on_response(self, resp):
        # http 목적지는 검문 프록시가 연결 실패 대신 거부 응답(403·502)을 돌려준다(https 는 위의 연결 실패로 잡힌다).
        # 평문 http 사이트가 이 헤더를 흉내 낼 수는 있지만, 그 결과는 자기 도메인을 목적지로 한 번 더 알리는 것뿐이다
        try:
            reason = resp.headers.get(EGRESS_HEADER.lower())
            if not reason or resp.status < 400:
                return
            req = resp.request
            if req.is_navigation_request() and _is_main_frame(req):
                self._note_blocked_destination(req.url, "egress:" + reason)
                self._egress_refused.add(req.url)
        except PWError:
            return

    # ── 관찰 ──────────────────────────────────────────
    async def _observe(self, page: Page, step: int) -> _Observation:
        self._act("read")
        try:
            raw = await page.evaluate(COLLECT_JS, [self.attr, self.s.max_candidates])
        except PWError:
            raw = {"items": [], "popup": False, "text": "", "title": ""}
        infos: dict[str, ElementInfo] = {}
        cands: list[tuple[int, Candidate]] = []
        forbidden: list[str] = []
        forbidden_ids: list[str] = []  # forbidden 과 같은 순서의 요소 ID(화면 위 상자용)
        ocr = get_ocr() if self.s.ocr_enabled else None
        # OCR 은 조사 마감과 관찰당 상한 중 이른 시각까지만 한다. 화면 안·큰 요소부터 읽어 중요한 버튼을 먼저 처리한다
        ocr_until = time.monotonic() + min(self.budget.remaining(), self.s.ocr_observe_max_seconds)
        ocr_skipped = 0
        dead_hosts = {b["host"] for b in self.result.blocked_destinations}
        items = raw.get("items", [])[: self.s.max_candidates * 4]
        items = sorted(items, key=lambda it: (0 if it.get("inView") else 1, -int(it.get("area") or 0)))
        # 1) DOM 금지 분류, 글자 없는 이미지 버튼은 캡처만 모은다(마감까지)
        entries: list[list] = []  # [item, info, eid, 캡처 번호 | None | "skip"]
        need: list[tuple[int, str, ElementInfo]] = []  # 캡처할 이미지 버튼 (entries 번호, eid, info)
        for item in items:
            info = ElementInfo.from_js(item)
            eid = str(item.get("id", ""))
            reason = classify_forbidden(info)
            if reason:
                label = (item.get("name") or info.text)[:30]
                forbidden.append(f"{reason}:{info.type or info.tag}:{mask_pii(label)}")
                forbidden_ids.append(eid)
                continue
            if not info.text and item.get("imgOnly") and ocr and ocr.available:
                need.append((len(entries), eid, info))
            entries.append([item, info, eid, None])
        shots: list[bytes] = []
        for (n, _, _), png in zip(need, await self._capture_many(page, need, ocr_until)):
            if png == "skip":
                entries[n][3] = "skip"
            elif png is not None:
                entries[n][3] = len(shots)
                shots.append(png)
        # 2) 모은 캡처를 한 번에 읽는다(모자이크)
        read = await ocr.read_many_async(shots, deadline=ocr_until) if shots else []
        # 3) 글자로 다시 금지 분류하고 선택지를 만든다
        for item, info, eid, shot_no in entries:
            if shot_no == "skip":
                ocr_skipped += 1  # 시간이 없어 읽지 않은 이미지 버튼: 무엇인지 모르므로 누르지 않는다
                continue
            text = info.text
            if shot_no is not None:
                text = read[shot_no]
                if text:
                    # OCR 로 얻은 글자로 다시 금지 분류(이미지 '결제' 버튼 등).
                    # 클릭 직전 비교용 지문은 DOM 원본(info)을 그대로 쓴다.
                    reason = classify_forbidden(ElementInfo(**{**info.__dict__, "text": text}))
                    if reason:
                        forbidden.append(f"{reason}:ocr:{mask_pii(text[:30])}")
                        forbidden_ids.append(eid)
                        continue
            if not text and item.get("imgOnly"):
                # 글자를 읽을 수 없는 이미지 버튼(OCR 없음·인식 실패)은 무엇인지 모르므로 누르지 않는다.
                # 이미지로 된 '결제' 버튼이 빈 이름으로 선택지에 오르는 것을 막는다.
                forbidden.append(f"unreadable_image:{info.tag}")
                forbidden_ids.append(eid)
                continue
            host = urlsplit(info.href).hostname if info.href.startswith("http") else None
            if (page.url, mask_pii(text)[:40]) in self._dead_links or host in dead_hosts:
                continue  # 이미 막다른 곳으로 이어진 버튼·링크(글자는 기록과 같은 40자로 비교)는 다시 내놓지 않는다
            if platform_link(page.url, info.href):
                continue  # 사이트 빌더 배지('Made in Framer')·'만든 곳' 링크: 누르면 조사 대상을 떠나 플랫폼 홍보 화면만 본다
            infos[eid] = info
            prio = (0 if item.get("inView") else 1, -int(item.get("area") or 0))
            cands.append((prio, Candidate(id=eid, tag=info.tag[:16], text=mask_pii(text)[:120],
                                          href_host=host, covered=bool(item.get("covered")))))
        cands.sort(key=lambda x: x[0])
        chosen = [c for _, c in cands[: self.s.max_candidates]]
        infos = {c.id: infos[c.id] for c in chosen}
        text = mask_pii(raw.get("text", ""))[:4000]
        state = PageState(step=step, url=page.url[:2048], title=mask_pii(raw.get("title", ""))[:200], text=text,
                          candidates=chosen, has_popup=bool(raw.get("popup")),
                          can_scroll=raw.get("scrollable") is not False, history=self.history[-30:])
        # 상자는 캡처 직전에 잰다(OCR 캡처가 스크롤을 되돌린 뒤), 크기는 실제 캡처 파일에서.
        # 스크롤이 잠긴 문서는 펼친 같은 상태에서 재고 찍는다(상자와 사진이 같은 배치)
        cand_ids, forb_ids = [c.id for c in chosen], forbidden_ids[:50]
        async with self._capture_layout(page) as expanded:
            root, rects = await measure_rects(page, self.attr, cand_ids + forb_ids)
            shot = await self._screenshot(page, "observe", full=True)
        boxes = boxes_from(root, rects, png_size(self.ev.file_path(shot)), cand_ids, len(forb_ids)) if shot else None
        text_hash = hashlib.sha256(raw.get("text", "").encode()).hexdigest()
        links = _page_links(raw.get("links"))
        seq = self._record("observe", {
            "step": step, "url": page.url[:2048], "title": state.title,
            "candidates": [c.model_dump() for c in chosen],
            "forbidden": forbidden[:50], "has_popup": state.has_popup,
            "text_excerpt": text[:1500], "text_sha256": text_hash, "ocr_skipped": ocr_skipped,
            "links_seen": len(links),
            **({"boxes": boxes} if shot and boxes else {}),
            **({"capture": "expanded"} if shot and expanded else {}),
        }, [shot] if shot else [])
        # 같은 화면 판정: URL·버튼 글자에 '남은 선택지'까지 넣는다. 효과 없던 행동이 빠져 선택지가 줄면 다른 상태로 보고
        # (줄어들기만 하므로 끝이 있다), 페이지를 오가는 진짜 반복은 그대로 잡는다.
        opts = "|".join(sorted(action_options(state)))
        key = hashlib.sha256((page.url + "|" + "|".join(c.text for c in chosen) + "#" + opts).encode()).hexdigest()
        return _Observation(state, infos, forbidden, seq, key, links)

    async def _capture_many(self, page: Page, need: list[tuple[int, str, ElementInfo]], until: float) -> list:
        """이미지 버튼들을 캡처한다(_capture_many_unpaused). 버튼을 찾아 위아래로 스크롤했다가 되돌리는 장면이
        콘솔 실시간 화면에서 튀지 않게 그동안 실시간 중계만 멈춘다(콘솔은 마지막 화면 유지). 녹화(증거)는 계속한다:
        스크롤하는 동안에만 보이는 내용이 있을 수 있어 증거에서는 빼지 않는다(Codex 지적)."""
        if need:
            self._act("ocr", len(need))
        if not need or not self.rec:
            return await self._capture_many_unpaused(page, need, until)
        self.rec.pause_live()
        try:
            return await self._capture_many_unpaused(page, need, until)
        finally:
            self.rec.resume_live()

    async def _capture_many_unpaused(self, page: Page, need: list[tuple[int, str, ElementInfo]], until: float) -> list:
        """이미지 버튼들을 캡처한다. 결과: PNG | None(보이지 않음) | "skip"(시간이 없어 찍지 않음).

        요소별 캡처는 요소마다 스크롤·안정 대기를 해 장당 약 0.7초가 걸린다. 여기서는 창 높이 단위로만
        스크롤하며, 위치를 새로 읽은 직후 창 한 장을 찍어 그 안에 온전히 들어온 버튼들을 잘라낸다.
        창 크기는 바꾸지 않으므로(페이지 전체 캡처와 달리) 레이아웃이 달라지지 않는다. 끝나면 스크롤을 되돌리고,
        잘라내지 못한 것(창보다 크거나 가로로 벗어남)만 요소별로 찍는다."""
        out: list = ["far"] * len(need)
        if not need:
            return out
        ids = [eid for _, eid, _ in need]
        start_y = None
        try:
            for _ in range(200):  # 아래로만 스크롤하므로 끝난다. 만일을 위한 상한
                left = [k for k in range(len(need)) if out[k] == "far"]
                if not left or time.monotonic() >= until:
                    break
                got = await page.evaluate(RECTS_JS, [self.attr, [ids[k] for k in left]])
                vw, vh, sy = int(got["vw"]), int(got["vh"]), float(got["sy"])
                start_y = sy if start_y is None else start_y
                inside, below = {}, []
                for k, r in zip(left, got["rects"]):
                    if r is None:
                        out[k] = None  # 보이지 않음: 찍지 않는다(읽을 수 없는 이미지로)
                        continue
                    x0, y0 = math.floor(r[0]), math.floor(r[1])
                    x1, y1 = math.ceil(r[0] + r[2]), math.ceil(r[1] + r[3])
                    if x0 >= 0 and y0 >= 0 and x1 <= vw and y1 <= vh:
                        inside[k] = (x0, y0, x1, y1)
                    elif x0 >= 0 and x1 <= vw and y1 - y0 <= vh:
                        below.append((y0 + sy, k))  # 스크롤하면 창에 들어온다
                    else:
                        out[k] = "one"  # 창보다 크거나 가로로 벗어남: 요소별로
                if inside:
                    shot = Image.open(io.BytesIO(await page.screenshot(timeout=8000)))
                    fx, fy = shot.width / vw, shot.height / vh
                    for k, (x0, y0, x1, y1) in inside.items():
                        buf = io.BytesIO()
                        shot.crop((round(x0 * fx), round(y0 * fy), round(x1 * fx), round(y1 * fy))).save(buf, "PNG")
                        out[k] = buf.getvalue()
                if not below:
                    break
                target = max(0.0, min(y for y, _ in below) - 8)
                if abs(target - sy) < 1:
                    for _, k in below:  # 스크롤해도 제자리(스크롤 끝): 요소별로
                        out[k] = "one"
                    break
                await page.evaluate(_SCROLL_TO_JS, target)
        except (PWError, PWTimeout, OSError, KeyError, TypeError, ValueError):
            pass  # 남은 것은 아래에서 요소별로
        finally:
            if start_y is not None:
                try:
                    await page.evaluate(_SCROLL_TO_JS, start_y)
                except PWError:
                    pass
        for k, (_, eid, info) in enumerate(need):
            if out[k] in ("far", "one"):
                out[k] = "skip" if time.monotonic() >= until else await self._capture_element(page, eid, info)
        return out

    async def _capture_element(self, page: Page, eid: str, info: ElementInfo) -> bytes | None:
        """이미지 버튼을 캡처한다(OCR 용). 지금 보이지 않는 요소는 찍지 않는다.

        Playwright 요소 스크린샷은 호출에 준 timeout 을 무시하고 페이지 기본 제한(30초)까지 기다린다(1.63 확인).
        관찰 뒤 숨는 캐러셀 배너나 숨은 hover 이미지 하나에 30초씩 멈추던 원인이라, 보이는지 먼저 보고
        그 사이에 숨는 경우에 대비해 찍는 동안만 기본 제한을 줄인다."""
        loc = page.locator(f"[{self.attr}='{eid}']").first
        page.set_default_timeout(_OCR_SHOT_TIMEOUT_MS)
        try:
            if info.tag != "img":
                imgs = loc.locator("img").filter(visible=True)
                if await imgs.count():
                    loc = imgs.first  # 인라인 <a> 박스는 이미지보다 작게 잘릴 수 있음
            if not await loc.is_visible():
                return None
            return await loc.screenshot(timeout=_OCR_SHOT_TIMEOUT_MS)
        except (PWError, PWTimeout):
            return None
        finally:
            page.set_default_timeout(_PW_DEFAULT_TIMEOUT_MS)

    # ── 실행 ──────────────────────────────────────────
    async def _read_element(self, page: Page, eid: str) -> ElementInfo | None:
        loc = page.locator(f"[{self.attr}='{eid}']")
        try:
            if await loc.count() != 1:
                return None
            return ElementInfo.from_js(await loc.first.evaluate(READ_ONE_JS))
        except PWError:
            return None

    def _is_dead_end(self, page: Page, blocked_before: int) -> bool:
        """더 조사할 것이 없는 화면인지: 브라우저 오류 화면, 검문 프록시 거부 화면, 목적지가 막힌 채 남은 빈 화면."""
        url = page.url
        if url.startswith("chrome-error://") or url in self._egress_refused:
            return True
        return url == "about:blank" and len(self.result.blocked_destinations) > blocked_before

    async def _leave_dead_end(self, page: Page, back_to: Page, url: str) -> Page | None:
        """막다른 곳에서 마지막 실제 페이지로 돌아간다. 돌아가지 못하면 None."""
        self._act("back")
        if page is not back_to:  # 새 창이 막다른 곳: 닫고 원래 창으로
            if self.rec:
                await self.rec.switch(back_to)
            try:
                await page.close()
            except PWError:
                pass
            page = back_to
        if page.url != url:
            try:
                await page.go_back(timeout=self.s.nav_timeout_ms)
            except (PWError, PWTimeout):
                pass
            await self._settle(page)
        return page if page.url == url else None

    async def _wait_auto_redirect(self, page: Page, state: PageState, step: int, url: str, blocked0: int) -> bool:
        """끝내기 전에, 스스로 넘어가는 대기 화면이면 잠시 기다려 본다. 넘어갔으면 True.
        단축 URL 서비스는 대기 화면을 몇 초 보여 준 뒤 목적지로 옮긴다. 그 전에 끝내면 목적지가 기록되지 않는다.
        url·blocked0 은 관찰하기 전의 주소와 열리지 않은 목적지 수다. 관찰·판단이 느려 그사이에 이미 넘어갔어도 알아챈다."""
        if url in self._waited or not is_auto_redirect_page(state.text):
            return False
        self._waited.add(url)
        self._act("redirect_wait")
        t0 = time.monotonic()
        until = t0 + min(_AUTO_REDIRECT_WAIT, max(0.0, self.budget.remaining() - 5))
        while time.monotonic() < until:
            if page.url != url or len(self.result.blocked_destinations) > blocked0:
                break
            await asyncio.sleep(0.25)
        moved = page.url != url or len(self.result.blocked_destinations) > blocked0
        if not moved and self._nav_checks:  # 기다리는 시간이 끝날 때 이동 검사가 진행 중이면 그 결과까지 본다
            await self._settle_nav_checks(page, step)
            moved = page.url != url or len(self.result.blocked_destinations) > blocked0
        if moved:
            await self._settle(page)
        self._record("wait_redirect", {"step": step, "url": url[:2048], "moved": moved,
                                       "result_url": page.url[:2048], "waited_ms": int((time.monotonic() - t0) * 1000),
                                       "destinations": [b["host"] for b in self.result.blocked_destinations[blocked0:]]})
        return moved

    async def _wait_new_controls(self, page: Page, obs: _Observation, step: int) -> bool:
        """끝내기 전에, 누를 것이 거의 없는 화면이면 잠시 기다려 누를 수 있는 요소가 새로 나타나는지 본다. 나타났으면 True.
        '잠시만 기다려 주세요' 뒤에 진행 버튼을 늦게 그리는 화면(단계형 시험 페이지 100종에서 도달 19%)을 첫 관찰만 보고 끝내지
        않게. 한 주소에 한 번, 누를 것이 _FEW_CONTROLS 개 이하이고 금지 요소가 없을 때만(누를 것이 많은 보통 화면, 입력칸이 있는
        목적지 화면은 기다리지 않는다)."""
        url = page.url
        # 입력·결제·다운로드 요소가 이미 보이는 화면은 목적지(위험 화면)라 기다리지 않는다(입력칸은 후보가 아니라 후보가 적다).
        # 관찰한 뒤 이미 다른 주소로 넘어갔으면 기다리지 않는다(호출한 쪽이 넘어간 곳을 다시 본다)
        if (url in self._waited_controls or len(obs.state.candidates) > _FEW_CONTROLS or obs.forbidden
                or url[:2048] != obs.state.url):
            return False
        self._waited_controls.add(url)
        n0 = await _count_controls(page)
        if n0 is None:
            return False
        self._act("load")
        t0 = time.monotonic()
        until = t0 + min(_CONTROLS_WAIT, max(0.0, self.budget.remaining() - 5))
        appeared = False
        while time.monotonic() < until:
            await asyncio.sleep(0.25)
            if page.url != url:
                break
            n = await _count_controls(page)
            if n is None:
                break
            if n > n0:
                appeared = True
                break
        self._record("wait_controls", {"step": step, "url": url[:2048], "appeared": appeared,
                                       "waited_ms": int((time.monotonic() - t0) * 1000)})
        return appeared

    async def _settle_nav_checks(self, page: Page, step: int) -> None:
        """주 화면 이동 요청을 검사하는 중이면 끝날 때까지 기다린다(검사 상한만큼).
        검사 중에 관찰하면 넘어가기 전 화면을 보고, 끝내면 목적지를 기록하기 전에 조사를 마친다."""
        if not self._nav_checks:
            return
        self._act("nav_check")
        t0 = time.monotonic()
        while self._nav_checks and time.monotonic() - t0 < _NAV_CHECK_TIMEOUT + 1:
            await asyncio.sleep(0.05)
        await self._settle(page)
        self._record("nav_check_wait", {"step": step, "url": page.url[:2048], "waited_ms": int((time.monotonic() - t0) * 1000),
                                        "pending": self._nav_checks})

    async def _settle(self, page: Page):
        self._act("load")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=3000)
        except (PWError, PWTimeout):
            pass

    async def _click_point(self, page: Page, eid: str) -> tuple[list[int] | None, bool]:
        """누를 요소를 창 안으로 옮기고(Playwright 클릭도 누르기 전에 하는 일) 창 기준 상자 [x, y, 폭, 높이]를 잰다.
        콘솔이 실시간 화면·녹화 재생 위에 클릭 표시를 그리는 데 쓴다(녹화 파일은 그대로). 상자는 페이지 JS 가 아니라
        브라우저 프로토콜로 잰다(measure_rects 와 같음). 못 재거나 창 밖이면 None — 클릭은 그대로 한다.
        게이트 검사 전에 부른다. 스크롤 뒤 화면 두 장을 기다려 페이지의 스크롤 처리(바꿔치기 포함)가 검사 전에 끝나게 한다.
        돌려주는 값: (상자, 옮기느라 요소가 움직였는지). 움직였으면 녹화 재생의 커서는 화면이 옮겨진 뒤에 버튼으로 간다
        (미리 가면 옮기기 전 화면의 엉뚱한 곳을 가리킨다). 옮기기 전 위치를 못 재면 움직인 것으로 본다."""
        vp = page.viewport_size
        if not _EID.fullmatch(eid) or not vp:
            return None, False
        loc = page.locator(f"[{self.attr}='{eid}']").first
        try:
            before = await loc.bounding_box(timeout=_BOX_TIMEOUT_MS)
        except (PWError, PWTimeout):
            before = None
        try:
            await loc.scroll_into_view_if_needed(timeout=2000)
        except (PWError, PWTimeout):
            return None, False
        try:  # 스크롤 이벤트는 다음 화면에 전달된다: 그 처리가 끝난 뒤 재고 검사한다(응답하지 않는 페이지는 1초까지만)
            await asyncio.wait_for(page.evaluate(_TWO_FRAMES_JS), 1.0)
        except (PWError, asyncio.TimeoutError):
            pass
        try:
            bb = await loc.bounding_box(timeout=_BOX_TIMEOUT_MS)
        except (PWError, PWTimeout):
            return None, False
        if not bb:
            return None, False
        moved = not before or abs(before["x"] - bb["x"]) > 1 or abs(before["y"] - bb["y"]) > 1
        x0, y0 = max(0.0, bb["x"]), max(0.0, bb["y"])
        x1, y1 = min(float(vp["width"]), bb["x"] + bb["width"]), min(float(vp["height"]), bb["y"] + bb["height"])
        if x1 - x0 < 1 or y1 - y0 < 1:
            return None, False
        return [round(x0), round(y0), max(1, round(x1 - x0)), max(1, round(y1 - y0))], moved

    async def _click(self, ctx: BrowserContext, page: Page, eid: str) -> tuple[Page, str]:
        """클릭하고 (현재 페이지, 결과)를 돌려준다. 결과: ok | failed | no_effect"""
        loc = page.locator(f"[{self.attr}='{eid}']").first
        before = (page.url, await self._text_digest(page))
        pages_before = set(ctx.pages)
        failed = False
        try:
            await loc.click(timeout=5000, no_wait_after=False)
        except (PWError, PWTimeout) as e:
            failed = True
            self._record("action_error", {"element": eid, "error": type(e).__name__})
        self._act("load")
        # 느린 사이트: 새 창은 첫 응답이 와야 잡히고 이동도 늦게 시작한다. 주소가 바뀌거나 새 창이 생길 때까지 최대 3초
        new_pages: list[Page] = []
        for _ in range(12):
            await asyncio.sleep(0.25)
            new_pages = [pg for pg in ctx.pages if pg not in pages_before]
            if new_pages or page.url != before[0] or await self._text_digest(page) != before[1]:
                break
        if new_pages:
            np = new_pages[-1]
            await self._settle(np)
            self._record("new_window", {"url": np.url[:2048], "adopted": True})
            if self.rec:
                await self.rec.switch(np)  # 녹화도 새 창을 따라간다
            return np, "ok"
        await self._settle(page)
        if failed:
            return page, "failed"
        if (page.url, await self._text_digest(page)) == before:
            return page, "no_effect"
        return page, "ok"

    async def _scroll_y(self, page: Page) -> float:
        try:
            return float(await page.evaluate("() => window.scrollY"))
        except (PWError, TypeError, ValueError):
            return -1.0

    async def _text_digest(self, page: Page) -> str:
        try:
            t = await page.evaluate("() => document.body ? document.body.innerText : ''")
        except PWError:
            return ""
        return hashlib.sha256(str(t).encode()).hexdigest()

    async def _close_popup(self, page: Page, offered: set[str], obs: _Observation) -> str:
        try:
            ids = await page.evaluate(CLOSE_POPUP_JS, self.attr)
        except PWError:
            ids = []
        for eid in ids:
            if eid in offered:
                cur = await self._read_element(page, eid)
                g = self.gate.check_click(offered, eid, obs.infos.get(eid), cur)
                if g.allowed:
                    await page.locator(f"[{self.attr}='{eid}']").first.click(timeout=3000)
                    await self._settle(page)
                    return f"clicked:{eid}"
        await page.keyboard.press("Escape")
        return "escape"

    # ── 메인 ──────────────────────────────────────────
    async def run(self) -> RunResult:
        g = self.gate.check_nav(self.start_url)
        self._record("start", {"url": self.start_url[:2048], "gate": g.reason,
                               "limits": {"steps": self.s.max_steps, "seconds": self.s.max_seconds}})
        if not g.allowed:
            return self._finish("BLOCKED", g.reason)

        video_tmp = self.ev.dir / f"{self._tag}video_tmp"
        async with async_playwright() as p:
            launch = {"headless": True, "args": _CHROMIUM_ARGS}
            if self.s.browser_channel:
                launch["channel"] = self.s.browser_channel
            if self.s.egress_proxy:
                launch["proxy"] = {"server": self.s.egress_proxy}
            browser: Browser = await p.chromium.launch(**launch)
            ua = browser_user_agent(self.s.browser_user_agent, browser.version)
            # 어떤 브라우저·User-Agent 로 조사했는지 증거에 남긴다(재현·설명용)
            self._record("browser", {"version": browser.version, "channel": self.s.browser_channel or "default",
                                     "user_agent": ua or "default"})
            ctx_kw = dict(
                viewport={"width": 1280, "height": 800}, locale="ko-KR", timezone_id="Asia/Seoul",
                accept_downloads=False, service_workers="block", java_script_enabled=True,
                ignore_https_errors=True, permissions=[],
            )
            if ua:
                ctx_kw["user_agent"] = ua
            ffmpeg = find_ffmpeg(self.s.ffmpeg_path) if self.s.record_video else None
            if self.s.record_video and not ffmpeg:
                # ffmpeg 가 없으면 Playwright 내장 녹화(창 크기 그대로)
                ctx_kw["record_video_dir"] = str(video_tmp)
                ctx_kw["record_video_size"] = {"width": 1280, "height": 800}
            ctx = await browser.new_context(**ctx_kw)
            await ctx.route("**/*", self._on_route)
            ctx.on("requestfailed", self._on_request_failed)
            ctx.on("response", self._on_response)
            ctx.on("page", lambda pg: pg.on("dialog", self._on_dialog))
            page = await ctx.new_page()
            page.on("dialog", self._on_dialog)
            rec_info = None
            if ffmpeg:
                self.rec = ScreencastRecorder(ffmpeg, self.ev.dir / f"{self._tag}recording.tmp.webm",
                                              live=self.live)
                try:
                    await self.rec.start(page)
                except (OSError, PWError) as e:
                    log.warning("recorder unavailable: %s", type(e).__name__)
                    self.rec = None
            try:
                await asyncio.wait_for(self._main_loop(ctx, page), max(self.budget.remaining(), 1.0) + _HARD_GRACE_S)
            except TimeoutError:  # 페이지가 응답하지 않아 예산 확인에 닿지 못함(무한 스크립트 등): 강제로 끝내고 담당자 검토
                log.warning("page unresponsive, hard deadline reached")
                self._record("page_unresponsive", {"seconds": round(time.monotonic() - self.budget.started, 1),
                                                   "limit": self.s.max_seconds + _HARD_GRACE_S})
                self.result.status, self.result.finish_reason = "REVIEW_REQUIRED", "page_unresponsive"
            except Exception as e:  # 실패는 삼키지 않고 기록 후 보류 처리
                log.exception("agent failed")
                self._record("error", {"error": type(e).__name__})
                self.result.status, self.result.finish_reason = "FAILED", f"error:{type(e).__name__}"
            finally:
                if self.rec:
                    rec_info = await _bounded(self.rec.stop(), "recorder.stop")
                await _bounded(ctx.close(), "context.close")
                await _bounded(browser.close(), "browser.close")
        if self.rec:
            self._save_recording(self.ev.dir / f"{self._tag}recording.tmp.webm", rec_info)
        else:
            self._save_video(video_tmp)
        self._act("judge")
        await asyncio.to_thread(self._judge)
        return self.result

    def _on_dialog(self, dialog):
        self._record("dialog", {"type": dialog.type, "message": mask_pii(dialog.message[:300])})
        asyncio.ensure_future(dialog.dismiss())

    async def _main_loop(self, ctx: BrowserContext, page: Page):
        main_frame_navs: list[str] = self.result.nav_chain

        def track(frame):
            # 오류 화면(chrome-error://)·about:blank·프록시 거부 화면은 열린 페이지가 아니다(경유 도메인·리다이렉트 수에 넣지 않음)
            if (frame == frame.page.main_frame and frame.url.startswith(("http://", "https://"))
                    and frame.url not in self._egress_refused
                    and (not main_frame_navs or main_frame_navs[-1] != frame.url)):
                main_frame_navs.append(frame.url[:2048])

        tracked = [page]
        page.on("framenavigated", track)
        # 첫 접속은 두 단계로 본다. 서버 응답(헤더)이 제한 안에 오지 않을 때만 접속 불가다.
        # 응답은 왔는데 화면 구성이 늦는 사이트(무거운 첫 화면, 부하 중인 조사 서버)는 기다린 만큼 보고 조사를 이어 간다
        self._act("open")
        try:
            resp = await page.goto(self.start_url, timeout=self.s.nav_timeout_ms, wait_until="commit")
        except (PWError, PWTimeout) as e:
            start_host = urlsplit(self.start_url).hostname
            moved = [b["host"] for b in self.result.blocked_destinations if b["host"] != start_host]
            if moved:
                # 시작 주소는 응답했지만 서버가 바로 넘긴 목적지가 열리지 않았다(단축 URL → 사라진 피싱 사이트).
                # 접속 불가가 아니라 막다른 곳이다: 화면은 없어도 목적지 이름을 근거로 위협 판단을 한다
                self._record("dead_end", {"step": 0, "url": self.start_url[:2048], "destinations": moved,
                                          "goto_error": classify_goto_error(e)})
                self.result.status, self.result.finish_reason = "COMPLETED", "dead_end"
                await self._wrap_up(page, 0)
                return
            info = classify_goto_error(e)
            if info["net_error"] in netfilter.DROPPED_ERRORS:
                # 연결은 됐는데 응답 없이 끊겼다: 사이트가 내려간 것인지, 회선이 이름을 보고 막은 것인지 확인한다
                info["network_filter"] = await asyncio.to_thread(
                    netfilter.probe, self.start_url, self.s.egress_proxy, set(self.s.test_allowlist))
                self.result.network_filtered = info["network_filter"]["filtered"]
            self._record("unreachable", info)
            self.result.status, self.result.finish_reason = "UNREACHABLE", "goto_failed"
            return
        refused = resp.headers.get(EGRESS_HEADER.lower()) if resp is not None and resp.status >= 400 else None
        if refused and resp.request.redirected_from is None:
            # 평문 http 시작 주소를 검문 프록시가 거부했다(상대에 연결 못 함): https 의 터널 실패와 같은 접속 불가다
            self._record("unreachable", {"error": "EgressRefused", "net_error": None, "category": "egress_refused",
                                         "egress_reason": refused[:64]})
            self.result.status, self.result.finish_reason = "UNREACHABLE", "goto_failed"
            return
        if netfilter.is_warning_page(page.url):
            # 회선이 차단 안내 페이지(warning.or.kr)로 보냈다: 사이트 화면은 볼 수 없다
            self._record("unreachable", {"error": "WarningPage", "net_error": None, "category": "network_filtered",
                                         "network_filter": {"method": "warning_page", "filtered": True,
                                                            "url": page.url[:2048]}})
            self.result.network_filtered = True
            self.result.status, self.result.finish_reason = "UNREACHABLE", "goto_failed"
            return
        t0 = time.monotonic()
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=self.s.nav_timeout_ms)
            dom_ready = True
        except (PWError, PWTimeout):
            dom_ready = False
        dom_ms = int((time.monotonic() - t0) * 1000)
        if resp is not None:
            chain = []
            r = resp.request
            while r.redirected_from is not None:
                r = r.redirected_from
                chain.append(r.url[:2048])
            self._record("navigation", {"status": resp.status, "redirects": list(reversed(chain)),
                                        "final_url": page.url[:2048],
                                        "dom_ready": dom_ready, "dom_wait_ms": dom_ms})
        await self._settle(page)

        step = 0
        last_real: tuple[Page, str] | None = None  # 마지막으로 관찰한 실제 페이지와 그 주소
        blocked_before = 0  # 직전 행동 전에 기록돼 있던 열리지 않은 목적지 수
        while True:
            over = self.budget.exceeded()
            if over:
                self.result.status, self.result.finish_reason = "COMPLETED", over
                break
            await self._settle_nav_checks(page, step)
            if self._is_dead_end(page, blocked_before):
                # 오류 화면·프록시 거부 화면에서는 할 수 있는 일이 없다('다시 시도'를 누르며 오가지 않는다).
                # 우리가 누른 링크 때문이면 그 링크를 빼고 원래 페이지로 돌아가 계속하고, 사이트가 스스로 옮겼으면 끝낸다
                self._record("dead_end", {"step": step, "url": page.url[:2048], "destinations": [
                    b["host"] for b in self.result.blocked_destinations[blocked_before:]]})
                last = self.history[-1] if self.history else ""
                back = None
                if last_real and last.startswith("click:") and last.count(":") >= 2:
                    self._dead_links.add((last_real[1], last.split(":", 2)[2]))
                    self.history[-1] = "dead_end:" + last.split(":", 1)[1]
                    back = await self._leave_dead_end(page, *last_real)
                if back is None:
                    self.result.status, self.result.finish_reason = "COMPLETED", "dead_end"
                    break
                page, blocked_before = back, len(self.result.blocked_destinations)
                continue
            observed_from = (page.url, len(self.result.blocked_destinations))
            obs = await self._observe(page, step)
            last_real = (page, page.url)
            self._note_links(obs)
            self.result.forbidden_seen.extend(x for x in obs.forbidden if x not in self.result.forbidden_seen)
            self.page_summaries.append(f"[{step}] {obs.state.title} | {obs.state.url} | {obs.state.text[:600]}")
            self.page_urls.append(obs.state.url[:2048])
            self.page_titles.append(obs.state.title[:200])
            self.page_forbidden.append([x[:300] for x in obs.forbidden[:50]])
            self.summary_evidence.append(obs.evidence_seq)
            self.emit({"type": "step", "step": step, "url": obs.state.url})
            loop = self.budget.observe_state(obs.state_key)
            if loop and self.history and self.history[-1] == "scroll":
                # 스크롤해도 고를 것이 그대로다(긴 안내문 아래의 버튼이 이미 후보에 있음): 끝내지 않고 스크롤을 뺀 선택지로
                # 한 번 더 고른다. 선택지가 줄어 같은 화면 판정 열쇠도 바뀌므로 끝이 있다
                self.history.append("scroll_no_effect")
                obs.state = obs.state.model_copy(update={"history": self.history[-30:]})
                loop = None
            if loop:
                self.result.status, self.result.finish_reason = "COMPLETED", loop
                break
            over = self.budget.exceeded()
            if over:  # 관찰(OCR·전체 캡처) 중에 시간을 다 썼으면 판단·행동을 하지 않고 이 관찰로 끝낸다
                self.result.status, self.result.finish_reason = "COMPLETED", over
                break

            self._act("decide")
            try:
                decision = await asyncio.to_thread(self.decider.action, obs.state)
            except DecisionUnavailable as e:
                self._record("decision_error", {"step": step, "error": str(e)[:200]})
                self.result.status, self.result.finish_reason = "REVIEW_REQUIRED", "decision_unavailable"
                break
            prob = decision.probabilities.get(decision.choice, 0.0)
            need = self.s.action_min_prob_click if decision.action == ActionKind.CLICK else self.s.action_min_prob
            self._record("decision", {
                "step": step, "choice": decision.choice, "probability": prob,
                "probabilities": dict(sorted(decision.probabilities.items(), key=lambda kv: -kv[1])[:10]),
                "provider": decision.provider, "model": decision.model, "latency_ms": decision.latency_ms,
                "observe_seq": obs.evidence_seq,
            })
            if prob < need or decision.action == ActionKind.FINISH:
                if await self._wait_auto_redirect(page, obs.state, step, *observed_from):
                    # 대기 화면이 스스로 다음 곳으로 넘어갔다: 끝내지 않고 넘어간 곳(막다른 곳 포함)을 이어서 본다
                    blocked_before = observed_from[1]
                    self.history.append("wait_redirect")
                    self.budget.steps += 1
                    step += 1
                    continue
                if await self._wait_new_controls(page, obs, step):
                    # 누를 것이 거의 없던 화면에 진행 버튼이 늦게 나타났다: 끝내지 않고 다시 관찰한다
                    self.history.append("waited")
                    self.budget.steps += 1
                    step += 1
                    continue
                await self._settle_nav_checks(page, step)
                if (self._is_dead_end(page, observed_from[1]) or len(self.result.blocked_destinations) > observed_from[1]
                        or page.url[:2048] != obs.state.url):
                    # 관찰·판단하는(기다리는) 사이에 페이지가 스스로 다른 곳으로 넘어갔다(대기 문구가 없는 자동 이동 화면,
                    # 열리지 않는 곳 포함): 끝내지 않고 넘어간 곳을 이어서 본다(막다른 곳이면 맨 위에서 처리한다)
                    blocked_before = observed_from[1]
                    self.history.append("moved")
                    self.budget.steps += 1
                    step += 1
                    continue
            if prob < need:
                # 다음 행동을 확신하지 못하면 탐색만 멈춘다. 담당자 검토 여부는 위협 판단(확신 부족 시 hold)에 맡긴다:
                # 탐색 확신도가 낮은 것과 위협 판단이 불확실한 것은 다르다.
                self.result.status, self.result.finish_reason = "COMPLETED", "low_confidence_action"
                break
            if decision.action == ActionKind.FINISH:
                self.result.status, self.result.finish_reason = "COMPLETED", "agent_finished"
                break
            if decision.action == ActionKind.BACK:
                # 누를 것이 거의 없는 화면에서 뒤로 가려 했는데 진행 버튼이 늦게 나타났거나, 기다리는(판단하는) 사이 페이지가
                # 스스로 다른 곳으로 넘어갔다: 돌아가지 않고 다시 관찰한다(늦게 그리는 중간 화면·'이동 중' 중간 화면과 앞 화면을
                # 오가다 같은 화면 반복으로 끝나던 것)
                appeared = await self._wait_new_controls(page, obs, step)
                if (appeared or page.url[:2048] != obs.state.url
                        or len(self.result.blocked_destinations) > observed_from[1]):
                    blocked_before = observed_from[1]
                    self.history.append("waited" if appeared else "moved")
                    self.budget.steps += 1
                    step += 1
                    continue

            blocked_before = len(self.result.blocked_destinations)
            before = await self._screenshot(page, "before")
            offered = set(obs.infos)
            outcome = ""
            if decision.action == ActionKind.CLICK:
                # 클릭 표시 좌표는 게이트 검사 전에 잰다: 누르려고 창 안으로 옮기는 스크롤에 페이지가 반응해 요소를 바꿔도
                # (결제 버튼으로 바꿔치기) 검사가 스크롤 뒤의 요소를 본다(Codex 지적: 검사 뒤에 스크롤하면 바뀐 요소를 눌렀다)
                self._act("click")
                point, scrolled = await self._click_point(page, decision.element_id or "")
                cur = await self._read_element(page, decision.element_id or "")
                gate = self.gate.check_click(offered, decision.element_id, obs.infos.get(decision.element_id or ""), cur)
                point = point if gate.allowed else None
                if point and self.live:
                    self.live.click(point)  # 콘솔 실시간 화면의 클릭 표시(영상과 같은 통로라 누르기 직전 화면에 맞춰 보인다)
                self._record("gate", {"step": step, "action": "click", "element": decision.element_id,
                                      "allowed": gate.allowed, "reason": gate.reason,
                                      # 누르기 직전 창 기준 상자와 시각(녹화 t0 와 같은 시계, epoch 초), 누르려고 화면을
                                      # 옮겼는지: 콘솔 클릭 표시용
                                      **({"point": point, "at": round(time.time(), 3), "scrolled": scrolled}
                                         if point else {})})
                if not gate.allowed:
                    if gate.reason.startswith("ssrf:") and cur is not None:
                        self._note_blocked_destination(cur.href, gate.reason)  # 링크 목적지를 열 수 없어 누르지 않음
                    label = next((c.text for c in obs.state.candidates if c.id == decision.element_id), "")
                    self.history.append(f"blocked:{decision.element_id}:{label[:40]}")
                    self.budget.steps += 1
                    step += 1
                    continue
                page, click_result = await self._click(ctx, page, decision.element_id)
                if page not in tracked:
                    tracked.append(page)
                    page.on("framenavigated", track)
                outcome = f"click:{decision.element_id}" + ("" if click_result == "ok" else f":{click_result}")
            elif decision.action == ActionKind.SCROLL:
                self._act("scroll")
                y0 = await self._scroll_y(page)
                await page.mouse.wheel(0, 700)
                await asyncio.sleep(0.5)
                outcome = "scroll" if await self._scroll_y(page) != y0 else "scroll_no_effect"  # 더 내려갈 곳 없음
            elif decision.action == ActionKind.CLOSE_POPUP:
                self._act("click")
                outcome = "close_popup:" + await self._close_popup(page, offered, obs)
            elif decision.action == ActionKind.BACK:
                self._act("back")
                url0 = page.url
                try:
                    await page.go_back(timeout=self.s.nav_timeout_ms)
                except (PWError, PWTimeout):
                    pass
                await self._settle(page)
                outcome = "back"
                if not page.url.startswith(("http://", "https://")):
                    # 시작 페이지에서 뒤로 가면 about:blank 로 사이트를 벗어난다: 되돌리고 효과 없음으로 기록
                    try:
                        await page.go_forward(timeout=self.s.nav_timeout_ms)
                    except (PWError, PWTimeout):
                        pass
                    await self._settle(page)
                    outcome = "back_no_effect"
                elif page.url == url0:
                    outcome = "back_no_effect"
            after = await self._screenshot(page, "after")
            self._record("action", {"step": step, "action": decision.action.value, "element": decision.element_id,
                                    "result_url": page.url[:2048], "outcome": outcome},
                         [f for f in (before, after) if f])
            if decision.action == ActionKind.CLICK:
                # 실패·효과 없음도 그대로 알려 같은 행동을 되풀이하지 않게 한다
                label = next((c.text for c in obs.state.candidates if c.id == decision.element_id), "")
                prefix = {"ok": "click", "failed": "click_failed", "no_effect": "click_no_effect"}[click_result]
                self.history.append(f"{prefix}:{decision.element_id}:{label[:40]}")
            else:
                self.history.append(outcome)
            self.budget.steps += 1
            step += 1

        await self._wrap_up(page, step)

    async def _wrap_up(self, page: Page, step: int):
        """조사를 마무리한다: 최종 주소·전체 캡처·finish 기록·경유 도메인."""
        await self._settle_nav_checks(page, step)  # 검사 중인 목적지도 위협 판단에 넣는다
        self.result.steps = step
        # 오류 화면·빈 화면·프록시 거부 화면에서 끝났으면 마지막으로 열린 실제 페이지를 최종 주소로 둔다
        # (열리지 않은 목적지는 blocked_destinations 에 있다)
        final_url = page.url
        if not final_url.startswith(("http://", "https://")) or final_url in self._egress_refused:
            final_url = self.result.nav_chain[-1] if self.result.nav_chain else self.start_url
        self.result.final_url = final_url[:2048]
        async with self._capture_layout(page) as expanded:
            final = await self._screenshot(page, "final", full=True)
        self._record("finish", {"reason": self.result.finish_reason, "final_url": self.result.final_url,
                                "nav_chain": self.result.nav_chain[:50],
                                "blocked_requests": self.result.blocked_requests,
                                "blocked_destinations": self.result.blocked_destinations,
                                **({"capture": "expanded"} if final and expanded else {})},
                     [final] if final else [])
        self._collect_candidates()

    def _note_links(self, obs: _Observation):
        """관찰한 화면의 링크를 모은다(외부 링크 후보, 사건 전체 100개). 클릭 후보의 링크를 먼저, 그다음 화면의 나머지
        링크. 값은 페이지에서 온 것이라 candidates.select 가 다시 검사한다."""
        seen = self.result.links_found
        urls = {x["url"] for x in seen}
        clicks = [{"url": i.href, "text": mask_pii(i.text)[:TEXT_MAX]} for i in obs.infos.values() if len(i.href) <= 2048]
        for x in [*clicks, *obs.links]:
            if len(seen) >= 100:
                break
            if x["url"].startswith(("http://", "https://")) and x["url"] not in urls:
                urls.add(x["url"])
                seen.append(x)

    def _collect_candidates(self):
        """보조 기능: 연관 후보(경유 도메인·외부 링크). 하위 조사는 runner 가 정한다."""
        self.result.candidates_found = select_candidates(
            self.start_url, self.result.final_url, self.result.nav_chain, self.result.links_found,
            self.s.allowed_ports, self.s.test_allowlist)

    def _save_recording(self, tmp: Path, info: dict | None):
        if info and tmp.exists():
            name = f"{self._tag}recording.webm"
            shutil.move(str(tmp), self.ev.file_path(name))
            self._record("recording", info, [name])
        else:
            tmp.unlink(missing_ok=True)

    def _save_video(self, tmp: Path):
        if not tmp.exists():
            return
        vids = sorted(tmp.glob("*.webm"), key=lambda p: p.stat().st_mtime)
        if vids:
            name = f"{self._tag}recording.webm"
            shutil.move(str(vids[-1]), self.ev.file_path(name))
            self._record("recording", {"format": "webm"}, [name])
        shutil.rmtree(tmp, ignore_errors=True)

    def _judge(self):
        if self.result.status in {"BLOCKED", "UNREACHABLE"}:
            self._finish(self.result.status, self.result.finish_reason)
            return
        domains = []
        for u in [self.start_url, *self.result.nav_chain]:
            h = urlsplit(u).hostname
            if h and h not in domains:
                domains.append(h)
        req = ThreatRequest(
            url=self.start_url[:2048], final_url=(self.result.final_url or self.start_url)[:2048],
            redirect_count=max(0, len(self.result.nav_chain) - 1), domains=domains[:30],
            pages=self.page_summaries[-20:], page_urls=self.page_urls[-20:], page_titles=self.page_titles[-20:],
            page_forbidden=self.page_forbidden[-20:], forbidden_seen=self.result.forbidden_seen[:50],
            blocked_destinations=self.result.blocked_destinations[:20],
        )
        try:
            d = self.decider.threat(req)
        except DecisionUnavailable as e:
            self._record("threat_error", {"error": str(e)[:200]})
            self._finish("REVIEW_REQUIRED", "threat_decision_unavailable")
            return
        prob = d.probabilities.get(d.choice, 0.0)
        threat = {"threat": d.threat.value, "probability": prob, "probabilities": d.probabilities,
                  "hold": d.hold, "provider": d.provider, "model": d.model,
                  "evidence_seqs": self.summary_evidence[-20:]}
        if d.override:
            threat["override"] = d.override
        self._record("threat", threat)
        self.result.threat = threat
        status = self.result.status
        if d.hold and status == "COMPLETED":
            status = "REVIEW_REQUIRED"
        self._finish(status if status != "RUNNING" else "COMPLETED", self.result.finish_reason)

    def _finish(self, status: str, reason: str) -> RunResult:
        # 최종 상태 이벤트는 runner 가 Safe Browsing 기록까지 마친 뒤 한 번만 보낸다
        self.result.status, self.result.finish_reason = status, reason
        return self.result
