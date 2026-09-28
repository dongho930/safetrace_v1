# API · 판단 서비스 · 검문 프록시 공용 이미지 (브라우저 없음)
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pyproject.toml ./
COPY safetrace ./safetrace
RUN pip install --no-cache-dir . && rm -rf /root/.cache
USER app
EXPOSE 8000
CMD ["uvicorn", "safetrace.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
