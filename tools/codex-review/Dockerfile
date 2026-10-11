# Codex 보안 검토 전용 이미지. 검토할 코드 사본(/work, 읽기 전용)과 검토 전용 로그인 볼륨(/codex)만 붙인다.
# 개발 PC 의 .env·models·사용자 폴더는 이 컨테이너에 없다(docs/codex-review.md).
FROM node:22-slim
ARG CODEX_VERSION=0.162.1
RUN npm install -g @openai/codex@${CODEX_VERSION} && npm cache clean --force \
    && apt-get update && apt-get install -y --no-install-recommends ripgrep git ca-certificates && rm -rf /var/lib/apt/lists/*
ENV CODEX_HOME=/codex
RUN mkdir /codex /out && chown node:node /codex /out
USER node
WORKDIR /work
ENTRYPOINT ["codex"]
