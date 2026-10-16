ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_FIND_LINKS=
ARG PIP_NO_INDEX=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN PIP_FIND_LINKS="${PIP_FIND_LINKS}" PIP_NO_INDEX="${PIP_NO_INDEX}" \
    pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" -r /app/requirements.txt
ARG DEBIAN_MIRROR=https://deb.debian.org
RUN if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && python -m playwright install-deps chromium
ARG PLAYWRIGHT_DOWNLOAD_HOST=
RUN PLAYWRIGHT_DOWNLOAD_HOST="${PLAYWRIGHT_DOWNLOAD_HOST}" python -m playwright install chromium \
    && chmod -R a+rX /ms-playwright

RUN useradd --uid 10001 --create-home inspection
COPY app.py api_auth.py operations.py artifact_store.py browser_executor.py migrate_config_v2.py migrate_api_auth_flows.py /app/
COPY static /app/static
USER 10001:10001

ARG RELEASE_VERSION=development
LABEL org.opencontainers.image.version=${RELEASE_VERSION}

ENTRYPOINT ["python", "/app/app.py"]
