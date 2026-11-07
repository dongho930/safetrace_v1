"""서비스 코드의 예외 처리가 광범위하게만 잡지 않게(2라운드 진단: 행안부 Python 04.03 부적절한 예외 처리, 21건).

진단 도구(Sparrow, 체커 OVERLY_BROAD_CATCH)는 같은 try 에서 구체적인 예외 처리 없이 Exception·BaseException·맨 except 로만
잡는 곳을 걸었다. 앞에 구체적인 예외 처리가 있고 마지막에 포괄 처리가 있는 곳(agent/loop.py 의 TimeoutError → Exception)은
걸지 않았고, 이 규칙을 그대로 옮긴 아래 검사가 진단 대상 코드(5ee54c4)에서 진단 결과와 같은 21곳을 찾았다.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "safetrace"
BROAD = {"Exception", "BaseException"}


def _names(handler: ast.ExceptHandler) -> list[str]:
    if handler.type is None:
        return ["<bare>"]
    elts = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return [getattr(e, "id", getattr(e, "attr", "?")) for e in elts]


def broad_only_catches(tree: ast.AST) -> list[int]:
    """같은 try 에서 구체적인 예외 처리보다 먼저(또는 혼자) 나오는 포괄 예외 처리의 줄 번호."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try | ast.TryStar):
            continue
        specific = False
        for h in node.handlers:
            names = _names(h)
            broad = any(n in BROAD or n == "<bare>" for n in names)
            if broad and not specific:
                out.append(h.lineno)
            specific = specific or not broad
    return out


def _service_files():
    files = sorted(SRC.rglob("*.py"))
    assert len(files) > 40
    return files


def test_rule_matches_the_diagnosis_shape():
    hit = ast.parse("try:\n    f()\nexcept Exception:\n    log()\n")
    bare = ast.parse("try:\n    f()\nexcept:\n    log()\n")
    mixed = ast.parse("try:\n    f()\nexcept (Exception, OSError):\n    log()\n")
    ok = ast.parse("try:\n    f()\nexcept OSError:\n    log()\nexcept Exception:\n    log()\n")
    assert broad_only_catches(hit) == [3]
    assert broad_only_catches(bare) == [3]
    assert broad_only_catches(mixed) == [3]
    assert broad_only_catches(ok) == []


def test_no_broad_only_catch_in_service_code():
    found = []
    for f in _service_files():
        for line in broad_only_catches(ast.parse(f.read_text(encoding="utf-8"))):
            found.append(f"{f.relative_to(SRC).as_posix()}:{line}")
    assert found == []


def test_every_handler_does_something():
    """그냥 넘기는 처리(pass·...)가 없다: 오류 상황 대응 부재(04.02)가 되지 않게 적어도 기록한다."""
    empty = []
    for f in _service_files():
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ExceptHandler) and all(
                    isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                    for s in node.body):
                empty.append(f"{f.relative_to(SRC).as_posix()}:{node.lineno}")
    assert empty == []
