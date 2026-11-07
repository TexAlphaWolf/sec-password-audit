FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . && useradd --system --no-create-home --uid 10001 pwaudit

# No network is needed unless --hibp is used; no root, no writable filesystem, nothing stored.
USER pwaudit
WORKDIR /data
ENTRYPOINT ["pwaudit"]
CMD ["--help"]
