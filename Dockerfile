# Veil proxy, CPU-only. Models are downloaded at build time so the container runs
# fully offline inside the branch (HF_HUB_OFFLINE=1 at runtime).
# Layer order: dependencies -> models -> source, so a code change rebuilds in seconds.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/veil/models \
    UV_SYSTEM_PYTHON=1

RUN pip install --no-cache-dir uv==0.12.5
WORKDIR /opt/veil

# 1. Dependencies (CPU torch first, so the NER extra doesn't pull the CUDA build)
COPY pyproject.toml ./
RUN uv pip install --no-cache --index-url https://download.pytorch.org/whl/cpu torch \
 && python -c "import tomllib; d=tomllib.load(open('pyproject.toml','rb'))['project']; print('\n'.join(d['dependencies'] + d['optional-dependencies']['proxy'] + d['optional-dependencies']['ner']))" > /tmp/reqs.txt \
 && uv pip install --no-cache -r /tmp/reqs.txt

# 2. Models (GLiNER multi-PII for EN/multilingual, CAMeLBERT for Arabic), in one layer:
#    only the .bin weights for CAMeLBERT (transformers would also fetch a duplicate
#    safetensors conversion), and ownership set here -- a separate chown would copy the layer.
RUN useradd --system --uid 10001 --home /opt/veil veil \
 && python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')" \
 && python -c "from huggingface_hub import snapshot_download; snapshot_download('CAMeL-Lab/bert-base-arabic-camelbert-msa-ner', allow_patterns=['*.json', '*.txt', 'pytorch_model.bin'])" \
 && HF_HUB_OFFLINE=1 python -c "from transformers import pipeline; pipeline('ner', model='CAMeL-Lab/bert-base-arabic-camelbert-msa-ner')" \
 && chown -R veil /opt/veil/models

# 3. Source
COPY README.md ./
COPY src ./src
RUN uv pip install --no-cache --no-deps .

USER 10001
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    VEIL_DEVICE=cpu \
    VEIL_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('VEIL_PORT','8080')}/healthz\", timeout=4).status == 200 else 1)"

CMD ["gunicorn", "-c", "python:veil.gunicorn_conf", "veil.proxy:app_from_env()"]
