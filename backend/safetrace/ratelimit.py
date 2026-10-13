"""접속 주소(IP)별 로그인 실패 제한.

계정별 잠금(accounts.MAX_FAILED)만 있으면 한 주소에서 여러 아이디를 번갈아 넣는 시도(비밀번호 스프레이)를 막지 못하고,
틀린 비밀번호마다 Argon2id 계산(CPU)을 시킬 수 있다. 시도마다 먼저 한 칸을 잡고(take) 성공하면 그 칸만 돌려준다(give_back).
그래서 동시에 몰아 보내도 창 안의 실패는 한도를 넘지 못하고, 성공이 이전 실패를 지우지도 않는다(계정 하나를 가진
공격자가 수를 비우지 못하게). 한도에 닿은 주소는 창이 끝날 때까지 비밀번호 확인 없이 거절한다.

API 는 프로세스 하나로 돈다(Dockerfile CMD). 수는 메모리에 두며 재시작하면 비워진다. 주소 수는 상한을 둬 메모리를 지킨다.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Window:
    start: float
    used: int = 0
    reported: bool = False  # 이 창에서 막힘을 이미 알렸는지(감사 로그 한 번만)


class FailureLimiter:
    def __init__(self, max_failures: int, window_s: float, max_keys: int = 10_000, clock=time.monotonic):
        self.max_failures = max_failures
        self.window_s = window_s
        self.max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, _Window] = {}

    def _window(self, key: str, t: float) -> _Window:
        w = self._windows.get(key)
        if w is not None and t - w.start < self.window_s:
            return w
        if w is None and len(self._windows) >= self.max_keys:
            for k in [k for k, v in self._windows.items() if t - v.start >= self.window_s]:
                del self._windows[k]
            if len(self._windows) >= self.max_keys:  # 창 안의 주소가 상한만큼 많으면 가장 오래된 창부터 버린다
                del self._windows[min(self._windows, key=lambda k: self._windows[k].start)]
        w = self._windows[key] = _Window(t)
        return w

    def take(self, key: str) -> tuple[int, bool]:
        """시도 한 칸을 잡는다. 반환 (막혔으면 남은 초 또는 0, 이번이 이 창에서 처음 막힌 것인지)."""
        with self._lock:
            t = self._clock()
            w = self._window(key, t)
            if w.used < self.max_failures:
                w.used += 1
                return 0, False
            first, w.reported = not w.reported, True
            return max(1, int(w.start + self.window_s - t + 0.999)), first

    def give_back(self, key: str) -> None:
        """성공한 시도의 칸을 돌려준다(같은 창일 때만)."""
        with self._lock:
            w = self._windows.get(key)
            if w is not None and w.used > 0 and self._clock() - w.start < self.window_s:
                w.used -= 1

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()
