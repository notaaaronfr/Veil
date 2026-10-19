"""Gunicorn settings for the Veil proxy (used by the Docker image).

    gunicorn -c python:veil.gunicorn_conf "veil.proxy:app_from_env()"

Workers are recycled every VEIL_MAX_REQUESTS requests (with jitter so they never restart
together): any prompt residue a worker accumulated dies with it, with no downtime because
the other worker keeps serving. Each worker loads its own NER models (~2.3 GB RSS).
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
loglevel = os.environ.get("VEIL_LOG_LEVEL", "info").lower()


def on_starting(server):
    from veil.hardening import harden

    harden()  # the master too: it holds no request data, but keep it unreadable


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
