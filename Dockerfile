# Veil proxy, CPU-only. Reproducible: dependencies come from uv.lock (pinned, hash-checked;
# CPU torch on Linux), the base image is pinned by digest (multi-arch index), and the NER
# models are baked in so the container runs fully offline inside the branch.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

# ---------------------------------------------------------------- build
FROM ${PYTHON_IMAGE} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never HF_HOME=/opt/veil/models
RUN pip install --no-cache-dir uv==0.12.5
WORKDIR /opt/veil

# 1. locked dependencies only (cached until pyproject.toml / uv.lock change)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra proxy --extra ner

# 2. models (GLiNER multi-PII, CAMeLBERT Arabic NER; .bin only for CAMeLBERT to avoid a
#    duplicate safetensors conversion)
RUN .venv/bin/python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')" \
 && .venv/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('CAMeL-Lab/bert-base-arabic-camelbert-msa-ner', allow_patterns=['*.json', '*.txt', 'pytorch_model.bin'])" \
 && HF_HUB_OFFLINE=1 .venv/bin/python -c "from transformers import pipeline; pipeline('ner', model='CAMeL-Lab/bert-base-arabic-camelbert-msa-ner')"

# 3. the project itself
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra proxy --extra ner

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="veil" \
      org.opencontainers.image.description="Verified pseudonymisation proxy for LLM calls" \
      org.opencontainers.image.source="https://github.com/notaaaronfr/Veil"
RUN useradd --system --uid 10001 --home /opt/veil veil \
 && mkdir -p /var/lib/veil/ledger && chown -R veil /var/lib/veil
COPY --from=build --chown=veil /opt/veil/.venv /opt/veil/.venv
COPY --from=build --chown=veil /opt/veil/models /opt/veil/models
ENV PATH=/opt/veil/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/veil/models HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    VEIL_DEVICE=cpu VEIL_PORT=8080
USER 10001
WORKDIR /opt/veil
EXPOSE 8080
VOLUME ["/var/lib/veil/ledger"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('VEIL_PORT','8080')}/readyz\", timeout=4).status == 200 else 1)"

CMD ["gunicorn", "-c", "python:veil.gunicorn_conf", "veil.proxy:app_from_env()"]
