"""Gunicorn settings for the Veil proxy (used by the Docker image).

    gunicorn -c python:veil.gunicorn_conf "veil.proxy:app_from_env()"

Workers are recycled every VEIL_MAX_REQUESTS requests (with jitter so they never restart
together): any prompt residue a worker accumulated dies with it, with no downtime because
the other worker keeps serving. The master loads the NER models once and workers share them
copy-on-write, so memory stays near one copy however many workers run, and a SIGHUP config
reload does not reload the models.
"""

import os

bind = f"0.0.0.0:{os.environ.get('VEIL_PORT', '8080')}"
workers = int(os.environ.get("VEIL_WORKERS", "2"))
worker_class = "uvicorn_worker.UvicornWorker"
max_requests = int(os.environ.get("VEIL_MAX_REQUESTS", "2000"))
max_requests_jitter = max(1, max_requests // 10)
timeout = int(os.environ.get("VEIL_WORKER_TIMEOUT", "180"))  # model load + long upstream calls
graceful_timeout = 60
accesslog = None  # the Veil audit log replaces access logs (query strings could carry data)
control_socket_disable = True  # no runtime control interface: less attack surface, and the FS is read-only
loglevel = os.environ.get("VEIL_LOG_LEVEL", "info").lower()


def on_starting(server):
    from veil.hardening import harden
    from veil.tenancy import load_active

    harden()  # the master too: it holds no request data, but keep it unreadable
    load_active()  # an invalid config at first start fails fast (nothing to fall back to)
    # Load the NER models once in the master; workers share them copy-on-write. No inference
    # runs here, so no thread pools exist yet when the master forks.
    if os.environ.get("VEIL_NER", "1") not in ("0", "false", "no", "off"):
        from veil.ner import preload

        preload(os.environ.get("VEIL_DEVICE", "cpu"))


def on_reload(server):
    """SIGHUP: validate the new config in the master before any new worker uses it."""
    from veil.tenancy import load_active

    try:
        cfg = load_active()
        server.log.info("config reloaded: %d tenants, %d clients", len(cfg.tenants), len(cfg.clients))
    except Exception as e:  # keep serving with the last valid config
        server.log.error("config reload REJECTED, still serving the previous config: %s", e)


def post_fork(server, worker):
    from veil.hardening import harden

    harden()
    # Each worker gets its share of the cores; by default every worker's torch would use
    # all of them and the workers would fight (measured: 9.9 -> 3.6 req/s with 2 workers).
    try:
        import torch

        threads = int(os.environ.get("VEIL_TORCH_THREADS", max(1, (os.cpu_count() or 2) // workers)))
        torch.set_num_threads(threads)
        torch.set_num_interop_threads(1)
    except Exception:
        pass
