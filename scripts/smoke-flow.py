"""End-to-end smoke test of the Keystead M4 flow.

Drives the real application over HTTPS: first-run setup, TOTP enrolment, sign-in,
vault creation, secret creation, reveal, rollback, and the audit chain badge.

Checks the security properties that matter at the edge, not just that pages return 200:
the value must not appear in the secret page's HTML, the reveal must be POST-only,
and the reveal response must be no-store.
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

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:5208"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keeps 302s visible, so the tests can assert where the app sends you."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
    NoRedirect(),
)


def follow(status, headers, limit=5):
    """Follows redirects by hand and returns the final response."""
    body = ""
    while status in (301, 302, 303, 307, 308) and limit > 0:
        status, body, headers = request(headers["Location"])
        limit -= 1
    return status, body, headers


def next_totp_window(secret_b32, after_code=None):
    """Waits for a code that differs from the one just consumed.

    The server records the highest TOTP time step it has accepted and refuses anything at or
    below it, so a correct code is single-use. A test that reuses a code inside the same
    30-second window is therefore meant to fail.
    """
    deadline = time.time() + 35
    while time.time() < deadline:
        code = totp(secret_b32)
        if code != after_code:
            return code
        time.sleep(1)
    return totp(secret_b32)

PASSWORD = "thistle harbour velvet onion"
EMAIL = "ada@example.com"
SECRET_VALUE = "Server=db;Password=a-very-distinctive-secret-value"

failures = []
checks = 0


def check(label, condition, detail=""):
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        failures.append(label)


def request(path, data=None, headers=None, method=None):
    url = path if path.startswith("http") else BASE + path
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "keystead-smoke/1.0")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with opener.open(req) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), dict(error.headers)


def uuid_like():
    """A well-formed but unused vault id, for the cross-vault refusal check."""
    import uuid
    return uuid.uuid4()


def csrf(html):
    match = re.search(r'name="__keystead-csrf"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else None


def totp(secret_b32, step=30, digits=6):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = struct.pack(">Q", int(time.time()) // step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


print("\n=== 1. First-run setup ===")
status, html, _ = request("/setup")
check("setup page renders", status == 200, f"status {status}")
token = csrf(html)
check("setup form has an antiforgery token", token is not None)

status, html, _ = request("/setup", {
    "__keystead-csrf": token,
    "Input.WorkspaceName": "Platform Team",
    "Input.DisplayName": "Ada Lovelace",
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
    "Input.ConfirmPassword": PASSWORD,
})
check("workspace created", "Your workspace is ready" in html, f"status {status}")
check("recovery kit shows a key fingerprint", re.search(r'id="kcv">[a-f0-9]{16}', html) is not None)
check("recovery kit does not show the key itself", "KEYSTEAD_MASTER_KEY" not in html)

print("\n=== 2. Sign in: owner must enrol MFA ===")
jar.clear()
status, html, _ = request("/sign-in")
token = csrf(html)
status, html, headers = request("/sign-in", {
    "__keystead-csrf": token,
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
})
check("owner is redirected, not let straight in", status == 302, f"status {status}")
check("redirected to MFA enrolment", "/mfa/enrol" in headers.get("Location", ""),
      headers.get("Location", ""))

print("\n=== 3. TOTP enrolment ===")
status, html, _ = request("/mfa/enrol")
check("enrolment page renders", status == 200, f"status {status}")
shared = re.search(r"<code>([A-Z2-7]{32})</code>", html)
check("shared secret is shown once", shared is not None)
check("QR is inline SVG, not a remote image", "<svg" in html and "<img" not in html)

secret_b32 = shared.group(1)
token = csrf(html)
enrol_code = totp(secret_b32)
status, html, _ = request("/mfa/enrol", {
    "__keystead-csrf": token,
    "Input.Code": enrol_code,
})
check("enrolment completes", "Save your recovery codes" in html, f"status {status}")
codes = re.findall(r"<li>([0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5})</li>", html)
check("ten recovery codes issued", len(codes) == 10, f"got {len(codes)}")

print("\n=== 4. Full sign-in with second factor ===")
jar.clear()
status, html, _ = request("/sign-in")
token = csrf(html)
status, html, headers = request("/sign-in", {
    "__keystead-csrf": token,
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
})
check("password step asks for the code", "/sign-in/mfa" in headers.get("Location", ""),
      headers.get("Location", ""))

status, html, _ = request("/sign-in/mfa")
token = csrf(html)

# Replay guard: the enrolment above consumed its time step, so reusing a code from the same
# window is refused. Waiting for the next one is the realistic case, not a workaround.
status, _, _ = request("/sign-in/mfa", {
    "__keystead-csrf": token,
    "Input.Code": enrol_code,
})
check("a already-used code is refused as a replay", status == 200, f"status {status}")

fresh_code = next_totp_window(secret_b32, after_code=enrol_code)
status, html, _ = request("/sign-in/mfa")
token = csrf(html)
status, html, headers = request("/sign-in/mfa", {
    "__keystead-csrf": token,
    "Input.Code": fresh_code,
})
check("fresh code is accepted", status == 302, f"status {status}")

status, html, _ = request("/")
check("signed in and dashboard loads", status == 200 and "Platform Team" in html, f"status {status}")

print("\n=== 5. Create a vault ===")
status, html, _ = request("/vaults")
token = csrf(html)
status, html, headers = request("/vaults?handler=Create", {
    "__keystead-csrf": token,
    "Input.Name": "Production",
    "Input.Description": "Live credentials",
    "Input.ColorToken": "teal",
    "Input.RecoveryWindowDays": "30",
    "Input.PurgeProtection": "false",
})
check("vault creation redirects to the new vault", status == 302, f"status {status}")
status, html, _ = request("/vaults/production")
check("vault created and reachable", status == 200 and "Production" in html, f"status {status}")

print("\n=== 6. Store a secret ===")
token = csrf(html)
status, html, _ = request("/vaults/production?handler=Create", {
    "__keystead-csrf": token,
    "Input.Name": "ConnectionStrings--Default",
    "Input.Environment": "prod",
    "Input.Value": SECRET_VALUE,
    "Input.ContentType": "text/plain",
    "Input.TagKey": "owner",
    "Input.TagValue": "platform-team",
})
status, html, _ = request("/vaults/production")
check("secret listed", "ConnectionStrings--Default" in html, f"status {status}")
check("LIST PAGE DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in html)

secret_id = re.search(r"/secrets/([0-9a-f-]{36})", html).group(1)

print("\n=== 7. Secret detail page ===")
status, detail, _ = request(f"/vaults/production/secrets/{secret_id}")
check("detail page renders", status == 200, f"status {status}")
check("DETAIL PAGE DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in detail)
check("value is masked in markup", "•" in detail)
check("version history shown", "v1" in detail)

print("\n=== 8. Reveal ===")
reveal_token = re.search(r'data-csrf="([^"]+)"', detail).group(1)
status, body, headers = request(
    f"/vaults/production/secrets/{secret_id}?handler=Reveal",
    data=b"",
    headers={"X-Keystead-CSRF": reveal_token},
    method="POST",
)
check("reveal returns 200", status == 200, f"status {status} body {body[:200]}")
payload = json.loads(body) if status == 200 else {}
check("reveal returns the correct value", payload.get("value") == SECRET_VALUE)
check("reveal response is no-store", "no-store" in headers.get("Cache-Control", ""))
check("reveal states an auto-hide window", payload.get("autoHideSeconds") == 30)

# A GET naming the Reveal handler finds no OnGetReveal and falls back to OnGet, which renders
# the ordinary page. The property that matters is not the status code but that no GET can
# produce the value: that is what keeps secrets out of browser history and shared caches.
status, body, _ = request(f"/vaults/production/secrets/{secret_id}?handler=Reveal", method="GET")
check("NO GET CAN RETURN THE VALUE", SECRET_VALUE not in body, f"status {status}")

status, body, _ = request(
    f"/vaults/production/secrets/{secret_id}?handler=Reveal", data=b"", method="POST")
check("reveal without a CSRF token is refused", status == 400, f"status {status}")

print("\n=== 9. New version and rollback ===")
status, detail, _ = request(f"/vaults/production/secrets/{secret_id}")
token = csrf(detail)
request(f"/vaults/production/secrets/{secret_id}?handler=NewVersion", {
    "__keystead-csrf": token,
    "Input.Value": "a-replacement-value",
})
status, detail, _ = request(f"/vaults/production/secrets/{secret_id}")
check("version 2 stored", "v2" in detail, f"status {status}")

token = csrf(detail)
request(f"/vaults/production/secrets/{secret_id}?handler=Rollback", {
    "__keystead-csrf": token,
    "targetVersion": "1",
})
status, detail, _ = request(f"/vaults/production/secrets/{secret_id}")
check("rollback created version 3", "v3" in detail, f"status {status}")

reveal_token = re.search(r'data-csrf="([^"]+)"', detail).group(1)
status, body, _ = request(
    f"/vaults/production/secrets/{secret_id}?handler=Reveal",
    data=b"", headers={"X-Keystead-CSRF": reveal_token}, method="POST")
check("rolled-back value is the original", json.loads(body).get("value") == SECRET_VALUE)

print("\n=== 10. Audit log ===")
status, html, _ = request("/audit")
check("audit page renders", status == 200, f"status {status}")
check("CHAIN VERIFIED badge shown", "Chain verified" in html, "chain reported broken")
check("secret read is recorded", "SecretValueRead" in html)
check("vault creation is recorded", "VaultCreated" in html)
check("rollback is recorded", "SecretRolledBack" in html)
check("AUDIT LOG DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in html)

status, csvbody, headers = request("/audit?handler=Export")
check("CSV export works", status == 200 and "text/csv" in headers.get("Content-Type", ""))
check("CSV does not contain the value", SECRET_VALUE not in csvbody)


print("\n=== 11. Service identity ===")
status, html, _ = request("/identities")
check("identities page renders", status == 200, f"status {status}")
token = csrf(html)

vault_id = re.search(r'name="Input.ScopedVaultIds" value="([0-9a-f-]{36})"', html).group(1)

status, html, _ = request("/identities?handler=Create", {
    "__keystead-csrf": token,
    "Input.Name": "smoke-runner",
    "Input.ScopedVaultIds": vault_id,
    "Input.GrantWrite": "false",
})
check("identity created", "Copy this now" in html, f"status {status}")

client_id = re.search(r'id="issued-client-id">(ksid_[A-Z0-9]+)<', html).group(1)
client_secret = re.search(r'id="issued-secret">(ksd_live_[A-Z0-9]+_[A-Z0-9]{6})<', html).group(1)
check("client id issued", client_id.startswith("ksid_"))
check("client secret issued with prefix and checksum", client_secret.startswith("ksd_live_"))
check("snippets show the real endpoint", BASE.split("//")[1] in html)

status, html, _ = request("/identities")
check("secret is NOT shown again on reload", client_secret not in html)

print("\n=== 12. Machine API: token endpoint ===")
machine = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())


def api(path, data=None, headers=None, method=None):
    """Calls the API with no cookie jar, the way a real application would."""
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(BASE + path, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with machine.open(req) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), dict(error.headers)


status, body, headers = api("/api/v1/token", {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
})
check("token issued", status == 200, f"status {status} {body[:200]}")
tok = json.loads(body) if status == 200 else {}
check("token is a bearer token", tok.get("token_type") == "Bearer")
check("token response is no-store", "no-store" in headers.get("Cache-Control", ""))
check("token carries the vault scope", f"vault:{vault_id}:read" in tok.get("scope", ""))
check("token expires in under an hour", 0 < tok.get("expires_in", 0) <= 3600)

access = tok.get("access_token", "")
alg = json.loads(base64.urlsafe_b64decode(access.split(".")[0] + "=="))
check("token is signed with ES256", alg.get("alg") == "ES256")
check("token names its signing key", bool(alg.get("kid")))

status, body, _ = api("/api/v1/token", {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": "ksd_live_WRONGWRONGWRONG_ABCDEF",
})
check("wrong secret is refused with 401", status == 401, f"status {status}")
check("failure is a problem document", "invalid_client" in body)

status, body, _ = api("/api/v1/token", {
    "grant_type": "password",
    "client_id": client_id,
    "client_secret": client_secret,
})
check("unsupported grant type is refused", status == 400, f"status {status}")

print("\n=== 13. Machine API: reading secrets ===")
auth = {"Authorization": "Bearer " + access}

status, body, headers = api("/api/v1/vaults/" + vault_id + "/secrets", headers=auth)
check("list secrets works", status == 200, f"status {status} {body[:200]}")
check("LIST RESPONSE DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in body)
check("list response is no-store", "no-store" in headers.get("Cache-Control", ""))

name = urllib.parse.quote("ConnectionStrings--Default")
path = "/api/v1/vaults/" + vault_id + "/secrets/" + name + "?environment=prod"

status, body, headers = api(path, headers=auth)
check("get secret returns the value",
      status == 200 and json.loads(body).get("value") == SECRET_VALUE,
      f"status {status} {body[:200]}")
check("get secret is no-store", "no-store" in headers.get("Cache-Control", ""))
etag = headers.get("ETag", "")
check("get secret returns an ETag", etag.startswith('"'))

status, body, _ = api(path, headers={**auth, "If-None-Match": etag})
check("matching ETag returns 304", status == 304, f"status {status}")

versions_path = "/api/v1/vaults/" + vault_id + "/secrets/" + name + "/versions?environment=prod"
status, body, _ = api(versions_path, headers=auth)
check("list versions works", status == 200 and len(json.loads(body)) == 3, f"status {status}")
check("VERSIONS RESPONSE DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in body)

print("\n=== 14. Machine API: authentication and authorization ===")
status, body, headers = api("/api/v1/vaults/" + vault_id + "/secrets")
check("no token is refused with 401", status == 401, f"status {status}")
check("401 names the bearer scheme", "Bearer" in headers.get("WWW-Authenticate", ""))

status, _, _ = api("/api/v1/vaults/" + vault_id + "/secrets",
                   headers={"Authorization": "Bearer not.a.token"})
check("a rubbish token is refused", status == 401, f"status {status}")

tampered = access[:-4] + ("AAAA" if not access.endswith("AAAA") else "BBBB")
status, _, _ = api("/api/v1/vaults/" + vault_id + "/secrets",
                   headers={"Authorization": "Bearer " + tampered})
check("a tampered signature is refused", status == 401, f"status {status}")

status, body, _ = api(
    path,
    data=json.dumps({"value": "written-by-a-read-only-identity"}).encode(),
    headers={**auth, "Content-Type": "application/json"},
    method="PUT")
check("a read-only identity cannot write", status == 403, f"status {status} {body[:160]}")

status, _, _ = api("/api/v1/vaults/" + str(uuid_like()) + "/secrets", headers=auth)
check("a vault outside the grant is 404", status == 404, f"status {status}")

print("\n=== 15. Revocation takes effect immediately ===")
status, html, _ = request("/identities")
token = csrf(html)
identity_id = re.search(r'name="identityId" value="([0-9a-f-]{36})"', html).group(1)
request("/identities?handler=Revoke", {
    "__keystead-csrf": token,
    "identityId": identity_id,
})

status, _, _ = api("/api/v1/vaults/" + vault_id + "/secrets", headers=auth)
check("REVOKED IDENTITY CANNOT USE ITS EXISTING TOKEN", status == 401, f"status {status}")

status, _, _ = api("/api/v1/token", {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
})
check("revoked identity cannot get a new token", status == 401, f"status {status}")

print("\n=== 16. Audit covers the machine API ===")
status, html, _ = request("/audit")
check("token issuance is recorded", "TokenIssued" in html)
check("token denial is recorded", "TokenDenied" in html)
check("identity creation is recorded", "ServiceIdentityCreated" in html)
check("identity revocation is recorded", "ServiceIdentityRevoked" in html)
check("chain still verifies after API traffic", "Chain verified" in html)
check("AUDIT STILL DOES NOT CONTAIN THE VALUE", SECRET_VALUE not in html)
check("AUDIT DOES NOT CONTAIN THE CLIENT SECRET", client_secret not in html)

print(f"\n{'=' * 60}")
print(f"{checks - len(failures)}/{checks} checks passed")
if failures:
    print("FAILED:")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)
print("All checks passed.")
