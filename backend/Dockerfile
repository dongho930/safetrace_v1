# API · 판단 서비스 · 검문 프록시 · 서명 서비스 공용 이미지 (브라우저 없음)
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 app
# 빌드 중 PyPI 응답이 느릴 때 pip 가 15초 만에 포기하지 않게(빌드 때만 쓰는 ARG)
ARG PIP_DEFAULT_TIMEOUT=60
ARG PIP_RETRIES=8
WORKDIR /app
# 보고서 PDF 용 한국어 글꼴(나눔고딕, OFL)
RUN apt-get update && apt-get install -y --no-install-recommends fonts-nanum && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
COPY safetrace ./safetrace
RUN pip install --no-cache-dir . && rm -rf /root/.cache
# 서명 서비스 상태 볼륨: 새 볼륨이 이 디렉터리의 소유자(app)를 이어받는다
RUN mkdir /state && chown app:app /state
USER app
EXPOSE 8000
CMD ["uvicorn", "safetrace.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
