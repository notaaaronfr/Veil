"""Concurrency check against a running Veil + fake upstream: every reply must restore to
exactly its own request (no cross-session bleed), and nothing sensitive may reach upstream.

    uv run python bench/load.py http://localhost:18080 <client-key> [--n 60] [--concurrency 12]
"""

import argparse
import asyncio
import json
import re
import statistics
import time
from pathlib import Path

import httpx

RECEIVED = Path(__file__).parent / "out" / "received.jsonl"
FIRST = ["Priya", "Johan", "Mariam", "Omar", "Elena", "Tariq"]
LAST = ["Raghunathan", "Lindqvist", "Haddad", "Petrova", "Bashir", "Iyer"]


def prompt(i: int) -> tuple[str, list[str]]:
    name = f"{FIRST[i % 6]} {LAST[(i // 6) % 6]}"
    phone = f"+971 50 {100 + i:03d} {1000 + i:04d}"
    card = "4111 1111 1111 1111"
    text = f"Request {i}: write to {name} at {phone} about card {card} and invoice {i}."
    # full values; numbers compared with separators removed
    return text, [FIRST[i % 6], LAST[(i // 6) % 6], f"97150{100 + i:03d}{1000 + i:04d}", "4111111111111111"]


def leaked(secrets: list[str], body: str) -> list[str]:
    digits = re.sub(r"[^0-9]", "", body)
    return [s for s in secrets if (s in digits if s.isdigit() else s in body)]


async def one(client, url, key, i, lat):
    text, secrets = prompt(i)
    t = time.perf_counter()
    r = await client.post(url, headers={"api-key": key},
                          json={"messages": [{"role": "user", "content": text}]})
    lat.append((time.perf_counter() - t) * 1000)
    got = r.json()["choices"][0]["message"]["content"]
    return got == f"Here is what I received: {text}", secrets


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("key")
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--concurrency", type=int, default=12)
    a = ap.parse_args()
    RECEIVED.unlink(missing_ok=True)
    url = a.url + "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
    sem = asyncio.Semaphore(a.concurrency)
    lat: list[float] = []

    async with httpx.AsyncClient(timeout=120) as client:
        async def guarded(i):
            async with sem:
                return await one(client, url, a.key, i, lat)

        t0 = time.perf_counter()
        results = await asyncio.gather(*(guarded(i) for i in range(a.n)))
        wall = time.perf_counter() - t0

    # match each upstream body to its own request ("Request {i}:" is not sensitive)
    bodies = {}
    for line in RECEIVED.read_text().splitlines():
        content = json.loads(line)["body"]["messages"][0]["content"]
        bodies[int(re.match(r"Request (\d+):", content).group(1))] = content
    leaks = sorted({s for i, (_, secrets) in enumerate(results) for s in leaked(secrets, bodies[i])})
    exact = sum(ok for ok, _ in results)
    lat.sort()
    print(f"requests {a.n}, concurrency {a.concurrency}, wall {wall:.1f}s, {a.n / wall:.1f} req/s")
    print(f"exact restore {exact}/{a.n}   leaks to upstream: {leaks or 'none'}")
    print(f"latency p50 {statistics.median(lat):.0f} ms   p95 {lat[int(0.95 * (len(lat) - 1))]:.0f} ms")


if __name__ == "__main__":
    asyncio.run(main())
