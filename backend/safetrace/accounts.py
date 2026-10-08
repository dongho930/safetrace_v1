"""담당자 계정과 로그인 세션.

- 비밀번호는 Argon2id(argon2-cffi 기본값 = RFC 9106 저메모리 권장값)로만 저장한다
- 세션 토큰은 서버가 만든 난수이고, DB 에는 SHA-256 만 둔다(DB 가 새도 토큰을 쓸 수 없음)
- 같은 계정에 비밀번호가 연속으로 틀리면 잠시 잠근다. 없는 계정·잠긴 계정도 같은 응답·비슷한 시간이 걸린다
- 역할이 바뀌거나 비활성화·비밀번호 변경이 되면 그 계정의 세션을 모두 끊는다

계정 만들기(첫 관리자): docker compose exec api python -m safetrace.accounts add <이름> --role admin
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import re
import secrets
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select, update

from .store import AuthSession, Store, User, now

ROLES = {"viewer": 0, "investigator": 1, "reviewer": 2, "admin": 3}
USERNAME = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")
PASSWORD_MIN, PASSWORD_MAX = 12, 128
MAX_FAILED = 5
LOCK_FOR = timedelta(minutes=15)
SESSION_IDLE = timedelta(minutes=30)
SESSION_MAX = timedelta(hours=12)
_TOUCH_EVERY = timedelta(seconds=60)  # 마지막 사용 시각은 1분에 한 번만 쓴다

_ph = PasswordHasher()
# Argon2id 한 번에 64MiB 를 쓰므로, 로그인 요청이 몰려도 메모리가 넘치지 않게 동시에 4개까지만 계산한다
_hash_slots = threading.BoundedSemaphore(4)
_DUMMY_HASH = _ph.hash(secrets.token_hex(16))


class AccountError(ValueError):
    """사용자에게 그대로 보여 줘도 되는 계정 오류(정책 위반 등)."""


@dataclass(frozen=True)
class SessionUser:
    user_id: int
    username: str
    role: str


def _aware(dt: datetime | None) -> datetime | None:
    # SQLite 는 시간대를 저장하지 않는다(PostgreSQL 은 저장). 비교 전에 UTC 로 맞춘다
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def is_locked(u: User) -> bool:
    return (_aware(u.locked_until) or now()) > now()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    with _hash_slots:
        return _ph.hash(password)


def _verify(stored: str, password: str) -> bool:
    with _hash_slots:
        try:
            return _ph.verify(stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def check_username(username: str) -> str:
    if not USERNAME.match(username):
        raise AccountError("아이디는 영문 소문자로 시작하는 3~32자(영문 소문자·숫자·._-)여야 합니다")
    return username


def check_password(password: str, username: str) -> None:
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise AccountError(f"비밀번호는 {PASSWORD_MIN}~{PASSWORD_MAX}자여야 합니다")
    if username.lower() in password.lower():
        raise AccountError("비밀번호에 아이디를 넣을 수 없습니다")
    if len(set(password)) < 4:
        raise AccountError("비밀번호가 너무 단순합니다")


def check_role(role: str) -> str:
    if role not in ROLES:
        raise AccountError("알 수 없는 역할입니다")
    return role


def create_user(store: Store, username: str, password: str, role: str) -> User:
    check_username(username)
    check_password(password, username)
    check_role(role)
    pw_hash = hash_password(password)
    with store.session() as s, s.begin():
        if s.scalar(select(User).where(User.username == username)):
            raise AccountError("이미 있는 아이디입니다")
        u = User(username=username, password_hash=pw_hash, role=role)
        s.add(u)
    return u


def list_users(store: Store) -> list[User]:
    with store.session() as s:
        return list(s.scalars(select(User).order_by(User.id)))


def get_user(store: Store, username: str) -> User | None:
    with store.session() as s:
        return s.scalar(select(User).where(User.username == username))


def _revoke_all(s, user_id: int) -> None:
    s.execute(update(AuthSession).where(AuthSession.user_id == user_id).values(revoked=True))


def update_user(store: Store, username: str, *, role: str | None = None, active: bool | None = None,
                password: str | None = None, unlock: bool = False) -> User:
    """관리자 변경. 권한에 영향을 주는 변경이면 그 계정의 세션을 모두 끊는다."""
    if role is not None:
        check_role(role)
    pw_hash = None
    if password is not None:
        check_password(password, username)
        pw_hash = hash_password(password)
    with store.session() as s, s.begin():
        u = s.scalar(select(User).where(User.username == username))
        if u is None:
            raise LookupError(username)
        revoke = False
        if role is not None and role != u.role:
            u.role, revoke = role, True
        if active is not None and active != u.active:
            u.active, revoke = active, revoke or not active
        if pw_hash is not None:
            u.password_hash, u.password_changed_at, revoke = pw_hash, now(), True
        if unlock or pw_hash is not None:
            u.failed_logins, u.locked_until = 0, None
        if revoke:
            _revoke_all(s, u.id)
    return u


def login(store: Store, username: str, password: str) -> tuple[str, SessionUser, datetime] | None:
    """성공하면 (세션 토큰, 사용자, 만료 시각). 실패 이유는 반환하지 않는다(감사로그에만 남김)."""
    with store.session() as s, s.begin():
        u = s.scalar(select(User).where(User.username == username)) if USERNAME.match(username) else None
        t = now()
        if u is None or not u.active or is_locked(u):
            _verify(_DUMMY_HASH, password)  # 계정이 있는지 응답 시간으로 알 수 없게
            return None
        if not _verify(u.password_hash, password):
            u.failed_logins += 1
            if u.failed_logins >= MAX_FAILED:
                u.failed_logins, u.locked_until = 0, t + LOCK_FOR
            return None
        u.failed_logins, u.locked_until = 0, None
        if _ph.check_needs_rehash(u.password_hash):  # 해시 설정을 올렸을 때 다음 로그인에 갱신
            u.password_hash = hash_password(password)
        token = secrets.token_urlsafe(32)
        expires = t + SESSION_MAX
        s.add(AuthSession(token_hash=token_digest(token), user_id=u.id, created_at=t, last_seen=t, expires_at=expires))
        return token, SessionUser(u.id, u.username, u.role), expires


def login_failure_reason(store: Store, username: str) -> str:
    """감사로그용 실패 이유(응답에는 쓰지 않는다)."""
    u = get_user(store, username) if USERNAME.match(username) else None
    if u is None:
        return "unknown_user"
    if not u.active:
        return "inactive"
    if is_locked(u):
        return "locked"
    return "bad_password"


def resolve(store: Store, token: str) -> SessionUser | None:
    if not token or len(token) > 128:
        return None
    t = now()
    with store.session() as s, s.begin():
        sess = s.get(AuthSession, token_digest(token))
        if sess is None or sess.revoked:
            return None
        if _aware(sess.expires_at) <= t or _aware(sess.last_seen) + SESSION_IDLE <= t:
            sess.revoked = True
            return None
        u = s.get(User, sess.user_id)
        if u is None or not u.active:
            return None
        if t - _aware(sess.last_seen) >= _TOUCH_EVERY:
            sess.last_seen = t
        return SessionUser(u.id, u.username, u.role)


def logout(store: Store, token: str) -> None:
    with store.session() as s, s.begin():
        sess = s.get(AuthSession, token_digest(token))
        if sess is not None:
            sess.revoked = True


def change_password(store: Store, user_id: int, current: str, new: str) -> bool:
    """본인 비밀번호 변경. 성공하면 모든 세션이 끊기므로 다시 로그인해야 한다."""
    with store.session() as s:
        u = s.get(User, user_id)
    if u is None or not _verify(u.password_hash, current):
        return False
    check_password(new, u.username)
    update_user(store, u.username, password=new)
    return True


# ── 명령줄: 첫 관리자 만들기, 비밀번호 재설정, 잠금 풀기 ─────────────────
def _read_password(username: str, from_stdin: bool) -> str:
    if from_stdin:  # 스크립트용: echo ... | docker compose exec -T api python -m safetrace.accounts add ... --password-stdin
        pw = sys.stdin.readline().rstrip("\r\n")
    else:
        pw = getpass.getpass(f"{username} 비밀번호: ")
        if pw != getpass.getpass("한 번 더: "):
            raise AccountError("두 비밀번호가 다릅니다")
    check_password(pw, username)
    return pw


def main(argv: list[str] | None = None) -> int:
    from .config import get_settings

    ap = argparse.ArgumentParser(prog="python -m safetrace.accounts", description="SafeTrace 담당자 계정 관리")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="계정 만들기")
    a.add_argument("username")
    a.add_argument("--role", required=True, choices=list(ROLES))
    p = sub.add_parser("passwd", help="비밀번호 재설정(세션 모두 끊김, 잠금 해제)")
    p.add_argument("username")
    u = sub.add_parser("unlock", help="로그인 잠금 풀기")
    u.add_argument("username")
    for x in (a, p):
        x.add_argument("--password-stdin", action="store_true", help="비밀번호를 표준 입력 첫 줄에서 읽기")
    sub.add_parser("list", help="계정 목록")
    args = ap.parse_args(argv)

    store = Store(get_settings().database_url)
    try:
        if args.cmd == "add":
            check_username(args.username)
            create_user(store, args.username, _read_password(args.username, args.password_stdin), args.role)
            store.audit("cli", "user.create", detail=f"user={args.username} role={args.role}")
        elif args.cmd == "passwd":
            update_user(store, args.username, password=_read_password(args.username, args.password_stdin))
            store.audit("cli", "user.password_reset", detail=f"user={args.username}")
        elif args.cmd == "unlock":
            update_user(store, args.username, unlock=True)
            store.audit("cli", "user.unlock", detail=f"user={args.username}")
        else:
            for x in list_users(store):
                print(f"{x.username}\t{x.role}\t{'활성' if x.active else '비활성'}")
            return 0
    except AccountError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1
    except LookupError:
        print("오류: 없는 계정입니다", file=sys.stderr)
        return 1
    print("완료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
