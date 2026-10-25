#!/usr/bin/env bash
# SBOM(소프트웨어 구성 목록, CycloneDX JSON)을 만든다: 서비스가 실제로 설치하는 의존성 잠금 파일에서.
#
#   tools/make_sbom.sh          # 결과: sbom/backend-api.cdx.json, sbom/backend-agent.cdx.json, sbom/frontend.cdx.json
#
# - 파이썬: backend/requirements.lock(API·판단·검문 프록시·서명·수집 이미지), requirements-agent.lock(조사 컨테이너)
#   잠금 파일은 해시를 고정한 것이라 SBOM 의 버전이 이미지에 실제로 깔리는 버전과 같다
# - 콘솔: frontend/package-lock.json(npm ci 가 무결성 해시로 설치)
# - 도구는 다이제스트를 고정한 컨테이너 안에서 버전을 고정해 받는다(호스트에 아무것도 깔지 않는다)
# 잠금 파일을 바꾸면(의존성 추가·갱신) 이 스크립트를 다시 돌려 sbom/ 을 함께 커밋한다.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
PY_IMAGE="python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b"
NODE_IMAGE="node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53"
CDX_PY="cyclonedx-bom==7.2.1"
CDX_NPM="@cyclonedx/cyclonedx-npm@4.1.2"

winpath() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1
mkdir -p sbom

docker run --rm -v "$(winpath "$ROOT"):/src" -w /src "$PY_IMAGE" sh -c "
  pip install -q --root-user-action=ignore --disable-pip-version-check '$CDX_PY' &&
  cyclonedx-py requirements backend/requirements.lock --of JSON --output-reproducible -o sbom/backend-api.cdx.json &&
  cyclonedx-py requirements backend/requirements-agent.lock --of JSON --output-reproducible -o sbom/backend-agent.cdx.json"

docker run --rm -v "$(winpath "$ROOT/frontend"):/src:ro" -v "$(winpath "$ROOT/sbom"):/out" -w /src "$NODE_IMAGE" sh -c "
  npx --yes '$CDX_NPM' --package-lock-only --omit dev --output-reproducible --output-format JSON --output-file /out/frontend.cdx.json"

for f in sbom/*.cdx.json; do
  echo "$f: 구성요소 $(grep -c '\"bom-ref\"' "$f")"
done
