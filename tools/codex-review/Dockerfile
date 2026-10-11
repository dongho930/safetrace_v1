# Codex 보안 검토 전용 이미지. 검토할 코드 사본(/work, 읽기 전용)과 검토 전용 로그인 볼륨(/codex)만 붙인다.
# 개발 PC 의 .env·models·사용자 폴더는 이 컨테이너에 없다(docs/codex-review.md).
# 베이스 이미지는 다이제스트로 고정한다(같은 태그에 다른 내용이 올라와도 쓰지 않게). 올릴 때 다이제스트를 함께 바꾼다
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ARG CODEX_VERSION=0.162.1
RUN npm install -g @openai/codex@${CODEX_VERSION} && npm cache clean --force \
    && apt-get update && apt-get install -y --no-install-recommends ripgrep git ca-certificates && rm -rf /var/lib/apt/lists/*
ENV CODEX_HOME=/codex
RUN mkdir /codex /out && chown node:node /codex /out
USER node
WORKDIR /work
ENTRYPOINT ["codex"]
