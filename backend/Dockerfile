# API · 판단 서비스 · 검문 프록시 · 서명 서비스 공용 이미지 (브라우저 없음)
# 기본 이미지는 다이제스트로 고정한다(같은 태그에 다른 내용이 올라와도 쓰지 않게, 공급망)
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 app
# 빌드 중 PyPI 응답이 느릴 때 pip 가 15초 만에 포기하지 않게(빌드 때만 쓰는 ARG)
ARG PIP_DEFAULT_TIMEOUT=60
ARG PIP_RETRIES=8
WORKDIR /app
# 보고서 PDF 용 한국어 글꼴(나눔고딕, OFL)
RUN apt-get update && apt-get install -y --no-install-recommends fonts-nanum && rm -rf /var/lib/apt/lists/*
# 의존성은 해시를 고정한 잠금 파일(requirements.lock, uv pip compile --generate-hashes)로만 설치한다. 프로젝트 자체는
# 의존성 없이, 잠금 파일의 setuptools 로(빌드 격리 없이) 설치해 PyPI 에서 해시 없는 꾸러미를 받지 않는다
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock && rm -rf /root/.cache
COPY safetrace ./safetrace
RUN pip install --no-cache-dir --no-deps --no-build-isolation . && rm -rf /root/.cache
# 서명 서비스 상태 볼륨: 새 볼륨이 이 디렉터리의 소유자(app)를 이어받는다
RUN mkdir /state && chown app:app /state
USER app
EXPOSE 8000
CMD ["uvicorn", "safetrace.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
