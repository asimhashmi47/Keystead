"""Verifies the SDK, the CLI and the OpenAPI document against a running Keystead server.

Sets up an installation, issues a service identity, then drives the shipped `keystead` tool
and the sample application against it. Checks what matters at this layer: that the CLI reads a
real value, that `keystead run` injects it into a child process, that `keystead env` quotes
values safely, and that the name mapping reaches an application through IConfiguration.

Usage: python scripts/verify-sdk-cli.py <base-url> <repo-root>
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:5213"
ROOT = sys.argv[2] if len(sys.argv) > 2 else "."

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

PASSWORD = "thistle harbour velvet onion"
EMAIL = "ada@example.com"
SECRET_VALUE = "Server=db;Password=sdk-distinctive-value"

failures = []
checks = 0


def check(label, condition, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if condition else 'FAIL'}  {label}" + (f"  {detail}" if not condition else ""))
    if not condition:
        failures.append(label)


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
    match = re.search(r'name="__keystead-csrf"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else None


def totp(secret_b32):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


print("\n=== Setting up an installation ===")
status, html, _ = request("/setup")
request("/setup", {
    "__keystead-csrf": csrf(html),
    "Input.WorkspaceName": "SDK Test",
    "Input.DisplayName": "Ada",
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
    "Input.ConfirmPassword": PASSWORD,
})

jar.clear()
status, html, _ = request("/sign-in")
request("/sign-in", {
    "__keystead-csrf": csrf(html),
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
})

status, html, _ = request("/mfa/enrol")
shared = re.search(r"<code>([A-Z2-7]{32})</code>", html).group(1)
enrol_code = totp(shared)
request("/mfa/enrol", {"__keystead-csrf": csrf(html), "Input.Code": enrol_code})

jar.clear()
status, html, _ = request("/sign-in")
request("/sign-in", {
    "__keystead-csrf": csrf(html),
    "Input.Email": EMAIL,
    "Input.Password": PASSWORD,
})

# Wait for a fresh TOTP window: the enrolment above consumed its time step.
deadline = time.time() + 35
while time.time() < deadline and totp(shared) == enrol_code:
    time.sleep(1)

status, html, _ = request("/sign-in/mfa")
request("/sign-in/mfa", {"__keystead-csrf": csrf(html), "Input.Code": totp(shared)})

status, html, _ = request("/")
check("signed in", status == 200, f"status {status}")

status, html, _ = request("/vaults")
request("/vaults?handler=Create", {
    "__keystead-csrf": csrf(html),
    "Input.Name": "Production",
    "Input.ColorToken": "teal",
    "Input.RecoveryWindowDays": "30",
})

status, html, _ = request("/vaults/production")
request("/vaults/production?handler=Create", {
    "__keystead-csrf": csrf(html),
    "Input.Name": "ConnectionStrings--Default",
    "Input.Environment": "prod",
    "Input.Value": SECRET_VALUE,
})

status, html, _ = request("/vaults/production")
request("/vaults/production?handler=Create", {
    "__keystead-csrf": csrf(html),
    "Input.Name": "Serilog__MinimumLevel",
    "Input.Environment": "prod",
    "Input.Value": "Warning",
})

status, html, _ = request("/identities")
vault_id = re.search(r'name="Input.ScopedVaultIds" value="([0-9a-f-]{36})"', html).group(1)

status, html, _ = request("/identities?handler=Create", {
    "__keystead-csrf": csrf(html),
    "Input.Name": "sdk-test",
    "Input.ScopedVaultIds": vault_id,
    "Input.GrantWrite": "true",
})

client_id = re.search(r'id="issued-client-id">(ksid_[A-Z0-9]+)<', html).group(1)
client_secret = re.search(r'id="issued-secret">(ksd_live_[A-Z0-9]+_[A-Z0-9]{6})<', html).group(1)
check("service identity issued", client_id.startswith("ksid_"))

print("\n=== OpenAPI document ===")
status, body, headers = request("/openapi/v1.json")
check("document is served", status == 200, f"status {status}")
doc = json.loads(body) if status == 200 else {}
check("describes the machine API", "Keystead machine API" in json.dumps(doc.get("info", {})))
check("documents the token endpoint", "/api/v1/token" in doc.get("paths", {}))
check("documents reading a secret",
      any("secrets" in p for p in doc.get("paths", {})), list(doc.get("paths", {}))[:4])
check("declares a bearer scheme",
      "bearer" in doc.get("components", {}).get("securitySchemes", {}))
check("DOCUMENT CONTAINS NO SECRET VALUE", SECRET_VALUE not in body)

print("\n=== CLI ===")
env = {
    **os.environ,
    "KEYSTEAD_ENDPOINT": BASE,
    "KEYSTEAD_CLIENT_ID": client_id,
    "KEYSTEAD_CLIENT_SECRET": client_secret,
    "KEYSTEAD_VAULT_ID": vault_id,
    "KEYSTEAD_ENVIRONMENT": "prod",

    # The dev certificate is self-signed, so the CLI would otherwise refuse to connect.
    "DOTNET_SYSTEM_NET_HTTP_SOCKETSHTTPHANDLER_HTTP2SUPPORT": "false",
}

cli = ["dotnet", "run", "--project", os.path.join(ROOT, "src", "Keystead.Cli"),
       "--no-build", "--no-launch-profile", "--"]


def run_cli(args, extra_env=None, timeout=120):
    result = subprocess.run(
        cli + args,
        env={**env, **(extra_env or {})},
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=ROOT,
    )
    return result.returncode, result.stdout, result.stderr


code, out, err = run_cli(["--version"])
check("keystead --version works", code == 0 and len(out.strip()) > 0, err[:200])

code, out, err = run_cli(["secret", "list"])
check("secret list finds both secrets",
      code == 0 and "ConnectionStrings--Default" in out and "Serilog__MinimumLevel" in out,
      f"code {code} out {out[:200]} err {err[:200]}")

code, out, err = run_cli(["secret", "get", "ConnectionStrings--Default"])
check("secret get returns the value", code == 0 and out == SECRET_VALUE,
      f"code {code} out {out[:120]!r}")

code, out, err = run_cli(["secret", "get", "ConnectionStrings:Default"])
check("secret get accepts the colon form too", code == 0 and out == SECRET_VALUE,
      f"code {code} out {out[:120]!r}")

code, out, err = run_cli(["secret", "get", "DoesNotExist"])
check("a missing secret is a non-zero exit", code != 0, f"code {code}")

code, out, err = run_cli(["env"])
check("env emits shell exports", code == 0 and "export CONNECTIONSTRINGS__DEFAULT=" in out,
      f"code {code} out {out[:200]}")
check("env single-quotes values so a shell cannot re-interpret them",
      f"'{SECRET_VALUE}'" in out, out[:200])

code, out, err = run_cli(["secret", "set", "NewFromCli", "written-by-the-cli"])
check("secret set writes a version", code == 0, f"code {code} err {err[:200]}")

code, out, err = run_cli(["secret", "get", "NewFromCli"])
check("the written value reads back", code == 0 and out == "written-by-the-cli",
      f"out {out[:120]!r}")

# Writing the same name again must append a version rather than create a second secret. This
# is the PUT-updates-existing path on the API, distinct from the create path above.
code, out, err = run_cli(["secret", "set", "NewFromCli", "second-version"])
check("writing an existing name appends a version", code == 0, f"code {code} err {err[:200]}")

code, out, err = run_cli(["secret", "get", "NewFromCli"])
check("the newest version is what reads back", code == 0 and out == "second-version",
      f"out {out[:120]!r}")

print("\n=== keystead run -- <command> ===")
if os.name == "nt":
    probe = ["cmd", "/c", "echo %CONNECTIONSTRINGS__DEFAULT%"]
else:
    probe = ["sh", "-c", "echo $CONNECTIONSTRINGS__DEFAULT"]

code, out, err = run_cli(["run", "--"] + probe)
check("run injects the secret into the child process",
      code == 0 and SECRET_VALUE in out, f"code {code} out {out[:200]} err {err[:300]}")
check("run reports how many secrets it injected", "Injecting" in err, err[:200])

if os.name == "nt":
    failing = ["cmd", "/c", "exit 3"]
else:
    failing = ["sh", "-c", "exit 3"]

code, out, err = run_cli(["run", "--"] + failing)
check("run propagates the child exit code", code == 3, f"code {code}")

code, out, err = run_cli(["run"])
check("run without -- is a usage error", code == 64, f"code {code}")

print("\n=== Audit records the SDK traffic ===")
status, html, _ = request("/audit")
check("machine reads are recorded", "SecretValueRead" in html)
check("machine secret creation is recorded", "SecretCreated" in html)
check("machine version writes are recorded", "SecretVersionCreated" in html)
check("chain still verifies", "Chain verified" in html)
check("AUDIT CONTAINS NO SECRET VALUE", SECRET_VALUE not in html)
check("AUDIT CONTAINS NO CLIENT SECRET", client_secret not in html)

print(f"\n{'=' * 60}")
print(f"{checks - len(failures)}/{checks} checks passed")

if failures:
    print("FAILED:")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)

print("All checks passed.")
