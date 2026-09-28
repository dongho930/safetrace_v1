"""AI 브라우저 에이전트 루프: 관찰 → Jev 행동 선택 → 안전 게이트 → 실행·기록.

에이전트는 DB에 접근하지 않는다. 증거는 서명해 파일로 남기고, 진행 상황은 emit() 이벤트로만 내보낸다.
텍스트 입력 기능은 아예 구현하지 않았다(fill/type/press 호출 없음. Escape 키만 팝업 닫기에 사용).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext, Page, Route, async_playwright
from playwright.async_api import Error as PWError
from playwright.async_api import TimeoutError as PWTimeout

from ..config import Settings
from ..decision.client import Decider, DecisionUnavailable
from ..decision.schema import ActionKind, Candidate, PageState, ThreatRequest, action_options
from ..evidence import EvidenceWriter
from ..masking import mask_pii
from .gate import Budget, ElementInfo, SafetyGate, classify_forbidden
from .observe import CLOSE_POPUP_JS, COLLECT_JS, READ_ONE_JS
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
    candidates_found: list[str] = field(default_factory=list)
    blocked_requests: int = 0
    forbidden_seen: list[str] = field(default_factory=list)


@dataclass
class _Observation:
    state: PageState
    infos: dict[str, ElementInfo]
    forbidden: list[str]
    evidence_seq: int
    state_key: str


class AgentRun:
    def __init__(self, url: str, settings: Settings, decider: Decider, writer: EvidenceWriter, emit: Emit,
                 resolver=None):
        self.start_url = url
        self.s = settings
        self.decider = decider
        self.ev = writer
        self.emit = emit
        self.gate = SafetyGate(settings.allowed_ports, settings.test_allowlist, resolver)
        self.budget = Budget(settings.max_steps, settings.max_seconds, settings.max_same_state)
        self.attr = "data-st-" + secrets.token_hex(4)
        self.result = RunResult(status="RUNNING", finish_reason="")
        self.history: list[str] = []
        self.page_summaries: list[str] = []
        self.summary_evidence: list[int] = []
        self._shot = 0
        self._host_ok: dict[str, tuple[float, bool, str]] = {}

    # ── 기록 ──────────────────────────────────────────
    def _record(self, kind: str, data: dict, files: list[str] | None = None) -> int:
        rec = self.ev.append(kind, data, files)
        self.emit({"type": "evidence", "seq": rec["seq"], "kind": kind, "data": data,
                   "files": list(rec["files"].keys()), "hash": rec["hash"]})
        return rec["seq"]

    async def _screenshot(self, page: Page, label: str) -> str | None:
        self._shot += 1
        name = f"s{self._shot:03d}_{label}.png"
        try:
            png = await page.screenshot(timeout=8000, animations="disabled")
        except (PWError, PWTimeout):
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
        if req.method.upper() not in _ALLOWED_METHODS:
            reason = f"method:{req.method.upper()}"
        else:
            ok, why = await asyncio.to_thread(self._host_allowed, url)
            if not ok:
                reason = why
        if reason:
            self.result.blocked_requests += 1
            if req.is_navigation_request() or reason.startswith("method"):
                self._record("blocked_request", {"url": url[:500], "reason": reason,
                                                 "navigation": req.is_navigation_request()})
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    # ── 관찰 ──────────────────────────────────────────
    async def _observe(self, page: Page, step: int) -> _Observation:
        try:
            raw = await page.evaluate(COLLECT_JS, [self.attr, self.s.max_candidates])
        except PWError:
            raw = {"items": [], "popup": False, "text": "", "title": ""}
        infos: dict[str, ElementInfo] = {}
        cands: list[tuple[int, Candidate]] = []
        forbidden: list[str] = []
        ocr = get_ocr() if self.s.ocr_enabled else None
        for item in raw.get("items", [])[: self.s.max_candidates * 4]:
            info = ElementInfo.from_js(item)
            eid = str(item.get("id", ""))
            reason = classify_forbidden(info)
            if reason:
                label = (item.get("name") or info.text)[:30]
                forbidden.append(f"{reason}:{info.type or info.tag}:{mask_pii(label)}")
                continue
            text = info.text
            if not text and item.get("imgOnly") and ocr and ocr.available:
                try:
                    loc = page.locator(f"[{self.attr}='{eid}']").first
                    if info.tag != "img" and await loc.locator("img").count():
                        loc = loc.locator("img").first  # 인라인 <a> 박스는 이미지보다 작게 잘릴 수 있음
                    png = await loc.screenshot(timeout=3000)
                    text = await asyncio.to_thread(ocr.read, png)
                except (PWError, PWTimeout):
                    text = ""
                if text:
                    # OCR 로 얻은 글자로 다시 금지 분류(이미지 '결제' 버튼 등).
                    # 클릭 직전 비교용 지문은 DOM 원본(info)을 그대로 쓴다.
                    reason = classify_forbidden(ElementInfo(**{**info.__dict__, "text": text}))
                    if reason:
                        forbidden.append(f"{reason}:ocr:{mask_pii(text[:30])}")
                        continue
            if not text and item.get("imgOnly"):
                # 글자를 읽을 수 없는 이미지 버튼(OCR 없음·인식 실패)은 무엇인지 모르므로 누르지 않는다.
                # 이미지로 된 '결제' 버튼이 빈 이름으로 선택지에 오르는 것을 막는다.
                forbidden.append(f"unreadable_image:{info.tag}")
                continue
            infos[eid] = info
            host = urlsplit(info.href).hostname if info.href.startswith("http") else None
            prio = (0 if item.get("inView") else 1, -int(item.get("area") or 0))
            cands.append((prio, Candidate(id=eid, tag=info.tag[:16], text=mask_pii(text)[:120],
                                          href_host=host, covered=bool(item.get("covered")))))
        cands.sort(key=lambda x: x[0])
        chosen = [c for _, c in cands[: self.s.max_candidates]]
        infos = {c.id: infos[c.id] for c in chosen}
        text = mask_pii(raw.get("text", ""))[:4000]
        state = PageState(step=step, url=page.url[:2048], title=mask_pii(raw.get("title", ""))[:200], text=text,
                          candidates=chosen, has_popup=bool(raw.get("popup")), history=self.history[-30:])
        shot = await self._screenshot(page, "observe")
        text_hash = hashlib.sha256(raw.get("text", "").encode()).hexdigest()
        seq = self._record("observe", {
            "step": step, "url": page.url[:2048], "title": state.title,
            "candidates": [c.model_dump() for c in chosen],
            "forbidden": forbidden[:50], "has_popup": state.has_popup,
            "text_excerpt": text[:1500], "text_sha256": text_hash,
        }, [shot] if shot else [])
        # 같은 화면 판정: URL·버튼 글자에 '남은 선택지'까지 넣는다. 효과 없던 행동이 빠져 선택지가 줄면 다른 상태로 보고
        # (줄어들기만 하므로 끝이 있다), 페이지를 오가는 진짜 반복은 그대로 잡는다.
        opts = "|".join(sorted(action_options(state)))
        key = hashlib.sha256((page.url + "|" + "|".join(c.text for c in chosen) + "#" + opts).encode()).hexdigest()
        return _Observation(state, infos, forbidden, seq, key)

    # ── 실행 ──────────────────────────────────────────
    async def _read_element(self, page: Page, eid: str) -> ElementInfo | None:
        loc = page.locator(f"[{self.attr}='{eid}']")
        try:
            if await loc.count() != 1:
                return None
            return ElementInfo.from_js(await loc.first.evaluate(READ_ONE_JS))
        except PWError:
            return None

    async def _settle(self, page: Page):
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=3000)
        except (PWError, PWTimeout):
            pass

    async def _click(self, ctx: BrowserContext, page: Page, eid: str) -> tuple[Page, str]:
        """클릭하고 (현재 페이지, 결과)를 돌려준다. 결과: ok | failed | no_effect"""
        loc = page.locator(f"[{self.attr}='{eid}']").first
        new_pages: list[Page] = []

        def on_page(pg: Page):
            new_pages.append(pg)

        before = (page.url, await self._text_digest(page))
        ctx.on("page", on_page)
        failed = False
        try:
            await loc.click(timeout=5000, no_wait_after=False)
        except (PWError, PWTimeout) as e:
            failed = True
            self._record("action_error", {"element": eid, "error": type(e).__name__})
        await asyncio.sleep(0.8)
        ctx.remove_listener("page", on_page)
        if new_pages:
            np = new_pages[-1]
            await self._settle(np)
            self._record("new_window", {"url": np.url[:2048], "adopted": True})
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

        video_tmp = self.ev.dir / "video_tmp"
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
            if self.s.record_video:
                ctx_kw["record_video_dir"] = str(video_tmp)
                ctx_kw["record_video_size"] = {"width": 960, "height": 600}
            ctx = await browser.new_context(**ctx_kw)
            await ctx.route("**/*", self._on_route)
            ctx.on("page", lambda pg: pg.on("dialog", self._on_dialog))
            page = await ctx.new_page()
            page.on("dialog", self._on_dialog)
            try:
                await self._main_loop(ctx, page)
            except Exception as e:  # 실패는 삼키지 않고 기록 후 보류 처리
                log.exception("agent failed")
                self._record("error", {"error": type(e).__name__})
                self.result.status, self.result.finish_reason = "FAILED", f"error:{type(e).__name__}"
            finally:
                await ctx.close()
                await browser.close()
        self._save_video(video_tmp)
        await asyncio.to_thread(self._judge)
        return self.result

    def _on_dialog(self, dialog):
        self._record("dialog", {"type": dialog.type, "message": mask_pii(dialog.message[:300])})
        asyncio.ensure_future(dialog.dismiss())

    async def _main_loop(self, ctx: BrowserContext, page: Page):
        main_frame_navs: list[str] = self.result.nav_chain

        def track(frame):
            if frame == frame.page.main_frame and (not main_frame_navs or main_frame_navs[-1] != frame.url):
                main_frame_navs.append(frame.url[:2048])

        tracked = [page]
        page.on("framenavigated", track)
        try:
            resp = await page.goto(self.start_url, timeout=self.s.nav_timeout_ms, wait_until="domcontentloaded")
        except (PWError, PWTimeout) as e:
            self._record("unreachable", classify_goto_error(e))
            self.result.status, self.result.finish_reason = "UNREACHABLE", "goto_failed"
            return
        if resp is not None:
            chain = []
            r = resp.request
            while r.redirected_from is not None:
                r = r.redirected_from
                chain.append(r.url[:2048])
            self._record("navigation", {"status": resp.status, "redirects": list(reversed(chain)),
                                        "final_url": page.url[:2048]})
        await self._settle(page)

        step = 0
        while True:
            over = self.budget.exceeded()
            if over:
                self.result.status, self.result.finish_reason = "COMPLETED", over
                break
            obs = await self._observe(page, step)
            self.result.forbidden_seen.extend(x for x in obs.forbidden if x not in self.result.forbidden_seen)
            self.page_summaries.append(f"[{step}] {obs.state.title} | {obs.state.url} | {obs.state.text[:600]}")
            self.summary_evidence.append(obs.evidence_seq)
            self.emit({"type": "step", "step": step, "url": obs.state.url})
            loop = self.budget.observe_state(obs.state_key)
            if loop:
                self.result.status, self.result.finish_reason = "COMPLETED", loop
                break

            try:
                decision = await asyncio.to_thread(self.decider.action, obs.state)
            except DecisionUnavailable as e:
                self._record("decision_error", {"step": step, "error": str(e)[:200]})
                self.result.status, self.result.finish_reason = "REVIEW_REQUIRED", "decision_unavailable"
                break
            prob = decision.probabilities.get(decision.choice, 0.0)
            self._record("decision", {
                "step": step, "choice": decision.choice, "probability": prob,
                "probabilities": dict(sorted(decision.probabilities.items(), key=lambda kv: -kv[1])[:10]),
                "provider": decision.provider, "model": decision.model, "latency_ms": decision.latency_ms,
                "observe_seq": obs.evidence_seq,
            })
            if prob < self.s.action_min_prob:
                self.result.status, self.result.finish_reason = "REVIEW_REQUIRED", "low_confidence_action"
                break
            if decision.action == ActionKind.FINISH:
                self.result.status, self.result.finish_reason = "COMPLETED", "agent_finished"
                break

            before = await self._screenshot(page, "before")
            offered = set(obs.infos)
            outcome = ""
            if decision.action == ActionKind.CLICK:
                cur = await self._read_element(page, decision.element_id or "")
                gate = self.gate.check_click(offered, decision.element_id, obs.infos.get(decision.element_id or ""), cur)
                self._record("gate", {"step": step, "action": "click", "element": decision.element_id,
                                      "allowed": gate.allowed, "reason": gate.reason})
                if not gate.allowed:
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
                y0 = await self._scroll_y(page)
                await page.mouse.wheel(0, 700)
                await asyncio.sleep(0.5)
                outcome = "scroll" if await self._scroll_y(page) != y0 else "scroll_no_effect"  # 더 내려갈 곳 없음
            elif decision.action == ActionKind.CLOSE_POPUP:
                outcome = "close_popup:" + await self._close_popup(page, offered, obs)
            elif decision.action == ActionKind.BACK:
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

        self.result.steps = step
        self.result.final_url = page.url[:2048]
        final = await self._screenshot(page, "final")
        self._record("finish", {"reason": self.result.finish_reason, "final_url": self.result.final_url,
                                "nav_chain": self.result.nav_chain[:50],
                                "blocked_requests": self.result.blocked_requests},
                     [final] if final else [])
        self._collect_candidates()

    def _collect_candidates(self):
        """보조 기능: 경유 도메인 기록(추가 조사는 담당자 요청 시에만)."""
        start_host = urlsplit(self.start_url).hostname
        hosts = []
        for u in self.result.nav_chain:
            h = urlsplit(u).hostname
            if h and h != start_host and h not in hosts:
                hosts.append(h)
        self.result.candidates_found = hosts[:20]

    def _save_video(self, tmp: Path):
        if not tmp.exists():
            return
        vids = sorted(tmp.glob("*.webm"), key=lambda p: p.stat().st_mtime)
        if vids:
            name = "recording.webm"
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
            pages=self.page_summaries[-20:], forbidden_seen=self.result.forbidden_seen[:50],
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
