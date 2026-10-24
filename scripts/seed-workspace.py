"""Seeds a Keystead installation with realistic content.

Used to populate a running instance before capturing screenshots, and as a starting state for
the load test. Drives the real HTTP pipeline throughout: nothing is written behind the
application, so the seeded state is one a real operator could have produced.

Prints the owner's credentials and TOTP secret at the end so a browser session can be opened.

Usage: python scripts/seed-workspace.py <base-url>
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:5230"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
    NoRedirect(),
)

EMAIL = "ada.lovelace@northwind.example"
PASSWORD = "thistle harbour velvet onion"


def request(path, data=None, method=None):
    url = path if path.startswith("http") else BASE + path
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with opener.open(req) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), dict(error.headers)


def csrf(html):
    m = re.search(r'name="__keystead-csrf"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else None


def post(path, fields, token_from=None):
    _, html, _ = request(token_from or path)
    body = dict(fields)
    token = csrf(html)
    if token:
        body["__keystead-csrf"] = token
    return request(path, body)


def totp(secret_b32):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


print("Setting up the workspace...")
post("/setup", {
    "Input.WorkspaceName": "Northwind Platform",
    "Input.DisplayName": "Ada Lovelace",
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
    "Input.ConfirmPassword": PASSWORD,
})

jar.clear()
post("/sign-in", {"Input.Email": EMAIL, "Input.Password": PASSWORD})

_, html, _ = request("/mfa/enrol")
secret = re.search(r"<code>([A-Z2-7]{32})</code>", html).group(1)
enrol_code = totp(secret)
_, html, _ = post("/mfa/enrol", {"Input.Code": enrol_code}, token_from="/mfa/enrol")

recovery = re.findall(r"<li>([0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5})</li>", html)
print(f"  enrolled, {len(recovery)} recovery codes issued")

jar.clear()
post("/sign-in", {"Input.Email": EMAIL, "Input.Password": PASSWORD})

# A recovery code avoids waiting for the TOTP window to roll past enrolment.
post("/sign-in/recovery", {"Input.Code": recovery[0]}, token_from="/sign-in/recovery")

status, html, _ = request("/")
assert status == 200, f"sign-in failed: {status}"
print("  signed in")

VAULTS = [
    ("Production", "Live credentials for customer-facing services.", "rose", True),
    ("Staging", "Pre-production. Mirrors Production, different values.", "amber", False),
    ("Data Platform", "Warehouse, ETL and analytics connections.", "teal", False),
    ("Third Party", "Credentials issued to us by other vendors.", "violet", False),
]

print("Creating vaults...")
for name, description, colour, protect in VAULTS:
    post("/vaults?handler=Create", {
        "Input.Name": name,
        "Input.Description": description,
        "Input.ColorToken": colour,
        "Input.RecoveryWindowDays": "30",
        "Input.PurgeProtection": "true" if protect else "false",
    }, token_from="/vaults")
    print(f"  {name}")

SECRETS = {
    "production": [
        ("ConnectionStrings--Default", "Server=sql-prod-01.northwind.internal;Database=Orders;User Id=orders_app;Password=Xq7!vN2pLm9wReT4", "text/plain", 45, "owner", "platform-team"),
        ("ConnectionStrings--Reporting", "Server=sql-prod-ro.northwind.internal;Database=Orders;User Id=reporting;Password=Hn3$kZ8qWd5xBvY1", "text/plain", None, "owner", "platform-team"),
        ("Stripe--SecretKey", "sk_demo_51QxKvN2pLm9wReT4Hn3kZ8qWd5xBvY1aMc7Gf0JhSt6Up", "text/plain", 12, "owner", "payments"),
        ("Stripe--WebhookSecret", "whsec_demo_7vN2pLm9wReT4Hn3kZ8qWd5xBvY1aMc7", "text/plain", None, "owner", "payments"),
        ("SendGrid--ApiKey", "SG-demo.Xq7vN2pLm9wReT4.Hn3kZ8qWd5xBvY1aMc7Gf0JhSt6UpRd9Kw", "text/plain", 88, "owner", "comms"),
        ("Redis--ConnectionString", "redis-prod.northwind.internal:6380,password=Zm4!tQ9rXc2vNb8L,ssl=True", "text/plain", None, "tier", "cache"),
        ("Jwt--SigningKey", "aGVsbG8tdGhpcy1pcy1hLWRlbW9uc3RyYXRpb24ta2V5LW5vdC1yZWFs", "text/plain", 3, "owner", "platform-team"),
    ],
    "staging": [
        ("ConnectionStrings--Default", "Server=sql-stg-01.northwind.internal;Database=Orders;User Id=orders_app;Password=Stg!7vN2pLm9", "text/plain", None, "owner", "platform-team"),
        ("Stripe--SecretKey", "sk_demo_test_51QxKvN2pLm9wReT4Hn3kZ8qWd5xBvY1aMc7Gf0JhSt6Up", "text/plain", None, "owner", "payments"),
        ("SendGrid--ApiKey", "SG-demo.StgXq7vN2pLm9.Hn3kZ8qWd5xBvY1aMc7Gf0JhSt6UpRd9Kw", "text/plain", None, "owner", "comms"),
    ],
    "data-platform": [
        ("Snowflake--ConnectionString", "account=nw12345.eu-west-1;user=etl_service;password=Sn0w!Fl4keP4ss;warehouse=ETL_WH", "text/plain", 60, "owner", "data-team"),
        ("Airflow--FernetKey", "dGhpcy1pcy1hLWZlcm5ldC1rZXktZm9yLWRlbW9uc3RyYXRpb24tb25s", "text/plain", None, "owner", "data-team"),
        ("S3--SecretAccessKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "text/plain", 21, "owner", "data-team"),
    ],
    "third-party": [
        ("Twilio--AuthToken", "a1b2c3d4e5f6071829304a5b6c7d8e9f", "text/plain", 7, "vendor", "twilio"),
        ("Datadog--ApiKey", "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "text/plain", None, "vendor", "datadog"),
        ("Cloudflare--ApiToken", "v1.0-7vN2pLm9wReT4Hn3kZ8q-Wd5xBvY1aMc7Gf0JhSt6UpRd9Kw", "text/plain", -4, "vendor", "cloudflare"),
    ],
}

print("Storing secrets...")
count = 0
for slug, items in SECRETS.items():
    for name, value, content_type, expires_in_days, tag_key, tag_value in items:
        fields = {
            "Input.Name": name,
            "Input.Environment": "prod" if slug != "staging" else "staging",
            "Input.Value": value,
            "Input.ContentType": content_type,
            "Input.TagKey": tag_key,
            "Input.TagValue": tag_value,
        }

        if expires_in_days is not None:
            expiry = time.gmtime(time.time() + expires_in_days * 86400)
            fields["Input.ExpiresUtc"] = time.strftime("%Y-%m-%dT%H:%M:%S", expiry)
            fields["Input.RotationReminderDays"] = "14"

        post(f"/vaults/{slug}?handler=Create", fields, token_from=f"/vaults/{slug}")
        count += 1

print(f"  {count} secrets")

# A few extra versions, so the version timeline has something to show.
print("Adding versions and a rollback...")
_, html, _ = request("/vaults/production")
secret_ids = re.findall(r"/secrets/([0-9a-f-]{36})", html)

if secret_ids:
    first = secret_ids[0]
    post(f"/vaults/production/secrets/{first}?handler=NewVersion",
         {"Input.Value": "Server=sql-prod-01.northwind.internal;Database=Orders;User Id=orders_app;Password=Rotated!9wReT4Hn3k"},
         token_from=f"/vaults/production/secrets/{first}")
    post(f"/vaults/production/secrets/{first}?handler=NewVersion",
         {"Input.Value": "Server=sql-prod-02.northwind.internal;Database=Orders;User Id=orders_app;Password=Rotated!2pLm9wReT4"},
         token_from=f"/vaults/production/secrets/{first}")
    post(f"/vaults/production/secrets/{first}?handler=Rollback",
         {"targetVersion": "2"},
         token_from=f"/vaults/production/secrets/{first}")
    print("  3 extra versions on one secret, including a rollback")

MEMBERS = [
    ("grace.hopper@northwind.example", "Grace Hopper", "Admin"),
    ("alan.turing@northwind.example", "Alan Turing", "Contributor"),
    ("katherine.johnson@northwind.example", "Katherine Johnson", "Contributor"),
    ("margaret.hamilton@northwind.example", "Margaret Hamilton", "Reader"),
    ("barbara.liskov@northwind.example", "Barbara Liskov", "Reader"),
]

print("Adding members...")
for email, name, role in MEMBERS:
    post("/members?handler=Add", {
        "Input.Email": email,
        "Input.DisplayName": name,
        "role": role,
    }, token_from="/members")
    print(f"  {name} ({role})")

# Grant a couple of the non-admin members access to specific vaults.
_, html, _ = request("/members")
user_ids = re.findall(r'name="userId" value="([0-9a-f-]{36})"', html)
vault_options = re.findall(r'<option value="([0-9a-f-]{36})">([^<]+)</option>', html)

if user_ids and vault_options:
    for user_id in user_ids[:3]:
        for vault_id, _ in vault_options[:2]:
            post("/members?handler=Grant", {
                "userId": user_id,
                "vaultId": vault_id,
                "permission": "Read",
            }, token_from="/members")
    print(f"  granted vault access to {min(3, len(user_ids))} members")

print("Creating service identities...")
_, html, _ = request("/identities")
vault_ids = re.findall(r'name="Input.ScopedVaultIds" value="([0-9a-f-]{36})"', html)

IDENTITIES = [
    ("orders-api-prod", 0, True, ""),
    ("reporting-worker-prod", 0, False, "10.40.0.0/16"),
    ("etl-pipeline", 2 if len(vault_ids) > 2 else 0, False, ""),
    ("ci-deploy-runner", 1 if len(vault_ids) > 1 else 0, True, "198.51.100.0/24"),
]

for name, index, write, allowlist in IDENTITIES:
    if index < len(vault_ids):
        post("/identities?handler=Create", {
            "Input.Name": name,
            "Input.ScopedVaultIds": vault_ids[index],
            "Input.GrantWrite": "true" if write else "false",
            "Input.IpAllowlist": allowlist,
        }, token_from="/identities")
        print(f"  {name}")

# Reveal a few values so the audit log shows read activity.
print("Generating audit activity...")
_, html, _ = request("/vaults/production")
ids = re.findall(r"/secrets/([0-9a-f-]{36})", html)

reveals = 0
for secret_id in ids[:5]:
    _, detail, _ = request(f"/vaults/production/secrets/{secret_id}")
    m = re.search(r'data-csrf="([^"]+)"', detail)
    if m:
        status, _, _ = request(
            f"/vaults/production/secrets/{secret_id}?handler=Reveal",
            data=b"", method="POST")
        reveals += 1

# A couple of refused sign-ins, so the log is not uniformly green.
spare = http.cookiejar.CookieJar()
spare_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(spare),
    NoRedirect())

for attempt in range(2):
    try:
        req = urllib.request.Request(BASE + "/sign-in")
        with spare_opener.open(req) as r:
            page = r.read().decode("utf-8", "replace")
        token = csrf(page)
        body = urllib.parse.urlencode({
            "__keystead-csrf": token or "",
            "Input.Email": "someone.else@northwind.example",
            "Input.Password": "wrong",
        }).encode()
        with spare_opener.open(urllib.request.Request(BASE + "/sign-in", data=body)) as r:
            pass
    except urllib.error.HTTPError:
        pass

print(f"  {reveals} reveals and 2 refused sign-ins recorded")

print()
print("=" * 64)
print("Seeded. Sign in with:")
print(f"  Email:    {EMAIL}")
print(f"  Password: {PASSWORD}")
print(f"  TOTP:     {secret}")
print(f"  Recovery: {' '.join(recovery[1:4])}")
print("=" * 64)

with open("scripts/.seed-credentials.json", "w", encoding="utf-8") as handle:
    json.dump({
        "email": EMAIL,
        "password": PASSWORD,
        "totpSecret": secret,
        "recoveryCodes": recovery[1:],
    }, handle, indent=2)

print("Credentials written to scripts/.seed-credentials.json (gitignored).")
