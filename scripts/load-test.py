"""Puts concurrent load on a running Keystead instance and reports what happens.

Three scenarios, each with a stated question:

  machine-read  A thousand applications fetching a secret by name, the way a service does at
                startup. The hot path, and the one that writes an audit entry per read.
  human-page    A thousand concurrent dashboard loads from signed-in browsers. Read-heavy,
                several aggregate queries per request.
  write-storm   Concurrent writes of new secret versions. Every write appends to the audit
                hash chain, which is strictly sequential, so this is where contention shows.

Outcomes are counted by status rather than lumped together as errors. A 429 is the rate
limiter working as designed and is reported apart from a 5xx, which is not.

Usage: python scripts/load-test.py <base-url> [scenario ...]
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import struct
import sys
import time

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:5230"
WANTED = sys.argv[2:] or ["machine-read", "human-page", "write-storm"]

USERS = 1000
WRITES = 300
CONCURRENCY = 200
IDENTITIES = 8

HERE = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS = os.path.join(HERE, ".seed-credentials.json")

with open(CREDENTIALS, encoding="utf-8") as handle:
    creds = json.load(handle)

# The local instance runs on a development certificate, so the name will not match.
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def csrf(html):
    found = re.search(r'name="__keystead-csrf"[^>]*value="([^"]+)"', html)
    return found.group(1) if found else ""


def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


SESSION = os.path.join(HERE, ".seed-session.json")


async def sign_in(client):
    """Gets the seeded owner signed in, reusing a saved session when one still works.

    The session is cached because signing in is deliberately expensive and deliberately
    single-use at both steps: a recovery code is spent when it is used, and the TOTP replay
    guard refuses a code that has already been seen in its window. Both are correct, and
    neither is something a load harness should be fighting on every run.
    """
    if os.path.exists(SESSION):
        with open(SESSION, encoding="utf-8") as handle:
            for name, value in json.load(handle).items():
                client.cookies.set(name, value)

        if (await client.get("/")).status_code == 200:
            return

        client.cookies.clear()

    page = (await client.get("/sign-in")).text
    await client.post("/sign-in", data={
        "__keystead-csrf": csrf(page),
        "Input.Email": creds["email"],
        "Input.Password": creds["password"],
    })

    # A fresh window, because the code for this one may already have been spent.
    for attempt in range(3):
        page = (await client.get("/sign-in/mfa")).text
        response = await client.post("/sign-in/mfa", data={
            "__keystead-csrf": csrf(page),
            "Input.Code": totp(creds["totpSecret"]),
        })

        if (await client.get("/")).status_code == 200:
            break

        if attempt < 2:
            wait = 31 - (int(time.time()) % 30)
            print(f"  code refused ({response.status_code}); waiting {wait}s for the next window")
            await asyncio.sleep(wait)

    landing = await client.get("/")

    if landing.status_code != 200:
        raise SystemExit(f"could not sign in: {landing.status_code}")

    with open(SESSION, "w", encoding="utf-8") as handle:
        json.dump(dict(client.cookies), handle, indent=2)


class Stats:
    """Counts outcomes by status and keeps latencies for percentiles."""

    def __init__(self, name, question):
        self.name = name
        self.question = question
        self.latencies = []
        self.by_status = {}
        self.notes = []
        self.started = 0.0
        self.finished = 0.0

    def record(self, status, seconds):
        self.latencies.append(seconds)
        self.by_status[status] = self.by_status.get(status, 0) + 1

    def report(self):
        total = len(self.latencies)
        wall = max(self.finished - self.started, 1e-9)
        order = sorted(self.latencies)

        def pct(p):
            return order[min(len(order) - 1, int(len(order) * p))] * 1000 if order else 0.0

        ok = sum(n for s, n in self.by_status.items() if isinstance(s, int) and 200 <= s < 300)
        limited = self.by_status.get(429, 0)
        server = sum(n for s, n in self.by_status.items() if isinstance(s, int) and s >= 500)
        transport = sum(n for s, n in self.by_status.items() if not isinstance(s, int))

        print()
        print(f"  {self.name}")
        print(f"    {self.question}")
        print(f"    requests      {total} in {wall:.1f}s  ({total / wall:.0f}/s)")
        print(f"    succeeded     {ok}")
        print(f"    rate limited  {limited}" + ("   (the limiter doing its job)" if limited else ""))
        print(f"    server error  {server}" + ("   <-- a real failure" if server else ""))
        print(f"    transport     {transport}" + ("   <-- connection level" if transport else ""))

        if order:
            print(f"    latency       p50 {pct(0.50):.0f}ms   p95 {pct(0.95):.0f}ms   "
                  f"p99 {pct(0.99):.0f}ms   max {order[-1] * 1000:.0f}ms")

        print(f"    statuses      {dict(sorted(self.by_status.items(), key=lambda kv: str(kv[0])))}")

        for note in self.notes[:4]:
            print(f"    note          {note}")

        return {
            "scenario": self.name,
            "requests": total,
            "seconds": round(wall, 2),
            "perSecond": round(total / wall, 1),
            "ok": ok,
            "rateLimited": limited,
            "serverError": server,
            "transportError": transport,
            "p50ms": round(pct(0.50)),
            "p95ms": round(pct(0.95)),
            "p99ms": round(pct(0.99)),
            "maxMs": round(order[-1] * 1000) if order else 0,
            "statuses": {str(k): v for k, v in self.by_status.items()},
            "notes": self.notes[:8],
        }


async def drive(stats, work, count, concurrency):
    """Runs `count` units of work with at most `concurrency` in flight."""
    gate = asyncio.Semaphore(concurrency)

    async def one(index):
        async with gate:
            start = time.perf_counter()
            try:
                status = await work(index)
            except Exception as error:  # noqa: BLE001 - every failure mode is a result here
                status = type(error).__name__
                if len(stats.notes) < 20:
                    stats.notes.append(f"{status}: {str(error)[:140]}")
            stats.record(status, time.perf_counter() - start)

    stats.started = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(count)))
    stats.finished = time.perf_counter()


async def prepare(client):
    """Creates probe identities and finds a vault and some secret names to read."""
    page = (await client.get("/identities")).text
    vault_ids = re.findall(r'name="Input.ScopedVaultIds" value="([0-9a-f-]{36})"', page)

    if not vault_ids:
        raise SystemExit("no vaults to scope an identity to")

    issued = []

    for n in range(IDENTITIES):
        page = (await client.get("/identities")).text
        response = await client.post("/identities?handler=Create", data={
            "__keystead-csrf": csrf(page),
            "Input.Name": f"load-probe-{n:02d}",
            "Input.ScopedVaultIds": vault_ids[0],
            "Input.GrantWrite": "true",
        })

        body = response.text
        client_id = re.search(r'id="issued-client-id">([^<]+)<', body)
        secret = re.search(r'id="issued-secret">([^<]+)<', body)

        if client_id and secret:
            issued.append((client_id.group(1).strip(), secret.group(1).strip()))

    if not issued:
        raise SystemExit("no client credentials were issued; the create response changed shape")

    vaults = (await client.get("/vaults")).text
    slug = re.search(r'href="/vaults/([a-z0-9-]+)"', vaults).group(1)

    listing = (await client.get(f"/vaults/{slug}")).text
    names = sorted(set(re.findall(r">([A-Za-z0-9]+--[A-Za-z0-9]+)<", listing)))

    return issued, vault_ids[0], names


async def tokens_for(identities):
    """Exchanges each identity's credentials for a bearer token."""
    out = []

    async with httpx.AsyncClient(base_url=BASE, verify=ssl_ctx, timeout=30) as api:
        for client_id, secret in identities:
            response = await api.post("/api/v1/token", data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret,
            })

            if response.status_code == 200:
                out.append(response.json()["access_token"])
            else:
                print(f"    token refused for {client_id}: "
                      f"{response.status_code} {response.text[:120]}")

    return out


async def main():
    results = []
    limits = httpx.Limits(max_connections=CONCURRENCY + 64,
                          max_keepalive_connections=CONCURRENCY + 64)

    async with httpx.AsyncClient(base_url=BASE, verify=ssl_ctx, follow_redirects=True,
                                 timeout=30) as session:
        print("Preparing...")
        await sign_in(session)
        identities, vault_id, names = await prepare(session)
        print(f"  {len(identities)} machine identities, {len(names)} secret names")

        bearers = await tokens_for(identities)
        print(f"  {len(bearers)} bearer tokens")

        if not bearers:
            raise SystemExit("no tokens were issued; the machine scenarios cannot run")

        cookies = session.cookies

    if "machine-read" in WANTED:
        stats = Stats(
            f"machine-read   {USERS} applications fetching a secret by name",
            "Does the hot path hold, and what does the audit append cost per read?")

        async with httpx.AsyncClient(base_url=BASE, verify=ssl_ctx, timeout=60,
                                     limits=limits) as api:
            async def read(i):
                token = bearers[i % len(bearers)]
                name = names[i % len(names)] if names else "ConnectionStrings--Default"
                response = await api.get(
                    f"/api/v1/vaults/{vault_id}/secrets/{name}",
                    headers={"Authorization": f"Bearer {token}"})
                return response.status_code

            await drive(stats, read, USERS, CONCURRENCY)

        results.append(stats.report())

    if "human-page" in WANTED:
        stats = Stats(
            f"human-page     {USERS} concurrent dashboard loads",
            "Do the aggregate queries behind the dashboard hold up under a crowd?")

        async with httpx.AsyncClient(base_url=BASE, verify=ssl_ctx, timeout=60,
                                     cookies=cookies, limits=limits) as browser:
            async def page(i):
                response = await browser.get("/")
                return response.status_code

            await drive(stats, page, USERS, CONCURRENCY)

        results.append(stats.report())

    if "write-storm" in WANTED:
        stats = Stats(
            f"write-storm    {WRITES} concurrent writes through the audit chain",
            "The chain is sequential by design. Where does that stop being free?")

        async with httpx.AsyncClient(base_url=BASE, verify=ssl_ctx, timeout=120,
                                     limits=limits) as api:
            async def write(i):
                token = bearers[i % len(bearers)]
                response = await api.put(
                    f"/api/v1/vaults/{vault_id}/secrets/load-probe-{i:04d}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"value": f"value-{i}"})
                return response.status_code

            await drive(stats, write, WRITES, CONCURRENCY)

        results.append(stats.report())

    with open(os.path.join(HERE, ".load-test-results.json"), "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    print()
    print("Results written to scripts/.load-test-results.json")


asyncio.run(main())
