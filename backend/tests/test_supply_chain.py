"""공급망 고정이 풀리지 않게: 이미지 다이제스트, Actions 커밋 SHA, 해시 잠금 파일로만 설치, SBOM 도구도 같은 규칙.

빌드·CI·SBOM 스크립트에서 외부 코드를 받아 실행하는 줄을 읽어 확인한다(받는 코드의 무결성을 검사하지 않으면 CWE-494).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_base_images_are_pinned_by_digest():
    for rel in ("backend/Dockerfile", "backend/Dockerfile.agent", "frontend/Dockerfile"):
        froms = re.findall(r"^FROM\s+(\S+)", _read(rel), re.M)
        assert froms and all("@sha256:" in f for f in froms), (rel, froms)
    images = re.findall(r"^\s+image:\s*(\S+)", _read("docker-compose.yml"), re.M)
    assert images and all("@sha256:" in i for i in images), images


def test_actions_are_pinned_by_commit_sha():
    wf = _read(".github/workflows/security.yml")
    uses = re.findall(r"uses:\s*(\S+)", wf)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses
    for img in re.findall(r"image:\s*(\S+)", wf):
        assert "@sha256:" in img, img


def _pip_installs(text: str) -> list[str]:
    return [m.group(0) for m in re.finditer(r"pip install[^\n&;]*", text)]


def test_python_installs_use_hash_locked_files_only():
    for rel in ("backend/Dockerfile", "backend/Dockerfile.agent", ".github/workflows/security.yml", "tools/make_sbom.sh"):
        for cmd in _pip_installs(_read(rel)):
            # 잠금 파일(해시)로 받거나, 이미 받은 것만 쓰는 프로젝트 자체 설치(--no-deps --no-build-isolation)만 허용
            assert "--require-hashes" in cmd or ("--no-deps" in cmd and "--no-build-isolation" in cmd), (rel, cmd)


def test_sbom_tool_is_hash_locked_and_cannot_write_the_repo():
    sh = _read("tools/make_sbom.sh")
    assert "npx --yes" not in sh  # 받는 도구·하위 의존성을 고정하지 않고 실행한다
    assert re.search(r"npm ci\b[^\n]*--ignore-scripts", sh)  # 잠금 파일(무결성 해시)로, 설치 스크립트 없이
    lock = ROOT / "tools/sbom/requirements.lock"
    assert lock.exists() and "--hash=sha256:" in lock.read_text(encoding="utf-8")
    assert (ROOT / "tools/sbom/package-lock.json").exists()
    # 저장소를 통째로 쓰기 가능하게 넣지 않는다: 쓰기 가능한 마운트는 결과 폴더(sbom)뿐, 나머지는 읽기 전용
    mounts = re.findall(r'-v\s+"\$\(winpath\s+"([^"]+)"\):([^"\s]+)"', sh)
    assert mounts, sh
    for src, dst in mounts:
        if src.endswith("/sbom"):
            continue
        assert dst.endswith(":ro"), (src, dst)
        assert src != "$ROOT", src
