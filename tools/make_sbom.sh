#!/usr/bin/env bash
# SBOM(소프트웨어 구성 목록, CycloneDX JSON)을 만든다: 서비스가 실제로 설치하는 의존성 잠금 파일에서.
#
#   tools/make_sbom.sh          # 결과: sbom/backend-api.cdx.json, sbom/backend-agent.cdx.json, sbom/frontend.cdx.json
#
# - 파이썬: backend/requirements.lock(API·판단·검문 프록시·서명·수집 이미지), requirements-agent.lock(조사 컨테이너)
#   잠금 파일은 해시를 고정한 것이라 SBOM 의 버전이 이미지에 실제로 깔리는 버전과 같다
# - 콘솔: frontend/package-lock.json(npm ci 가 무결성 해시로 설치)
# - 도구는 다이제스트를 고정한 컨테이너 안에서, 도구와 하위 의존성 모두 해시로 잠근 파일로만 받는다
#   (tools/sbom/requirements.lock: pip --require-hashes·바이너리만, tools/sbom/package-lock.json: npm ci --ignore-scripts)
# - 컨테이너에는 읽을 잠금 파일만 읽기 전용으로, 쓰기는 결과 폴더(sbom/)만 넣는다(저장소·.env 를 넣지 않는다)
# 잠금 파일을 바꾸면(의존성 추가·갱신) 이 스크립트를 다시 돌려 sbom/ 을 함께 커밋한다.
# 도구를 올릴 때는 tools/sbom/requirements.in·package.json 의 버전을 바꾸고 README 의 명령으로 잠금 파일을 다시 만든다.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
PY_IMAGE="python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b"
NODE_IMAGE="node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53"

winpath() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1
mkdir -p sbom

docker run --rm \
  -v "$(winpath "$ROOT/backend/requirements.lock"):/in/requirements.lock:ro" \
  -v "$(winpath "$ROOT/backend/requirements-agent.lock"):/in/requirements-agent.lock:ro" \
  -v "$(winpath "$ROOT/tools/sbom/requirements.lock"):/tool/requirements.lock:ro" \
  -v "$(winpath "$ROOT/sbom"):/out" \
  -w /in "$PY_IMAGE" sh -c "
  pip install -q --root-user-action=ignore --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: -r /tool/requirements.lock &&
  cyclonedx-py requirements requirements.lock --of JSON --output-reproducible -o /out/backend-api.cdx.json &&
  cyclonedx-py requirements requirements-agent.lock --of JSON --output-reproducible -o /out/backend-agent.cdx.json"

docker run --rm \
  -v "$(winpath "$ROOT/frontend/package.json"):/src/package.json:ro" \
  -v "$(winpath "$ROOT/frontend/package-lock.json"):/src/package-lock.json:ro" \
  -v "$(winpath "$ROOT/tools/sbom/package.json"):/tool/package.json:ro" \
  -v "$(winpath "$ROOT/tools/sbom/package-lock.json"):/tool/package-lock.json:ro" \
  -v "$(winpath "$ROOT/sbom"):/out" \
  -w /src "$NODE_IMAGE" sh -c "
  mkdir /tmp/t && cp /tool/package.json /tool/package-lock.json /tmp/t/ &&
  npm ci --ignore-scripts --no-audit --no-fund --prefix /tmp/t -q &&
  /tmp/t/node_modules/.bin/cyclonedx-npm --package-lock-only --omit dev --output-reproducible --output-format JSON --output-file /out/frontend.cdx.json"

for f in sbom/*.cdx.json; do
  echo "$f: 구성요소 $(grep -c '\"bom-ref\"' "$f")"
done
