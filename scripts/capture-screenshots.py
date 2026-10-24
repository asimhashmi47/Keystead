"""Captures full-page screenshots of a running Keystead instance into images/.

Drives headless Chrome over the DevTools protocol. It signs in the way a person would, walks
the pages, answers the step-up challenge to reveal a value, and writes a 2x PNG of each page.
Nothing is staged: every screenshot is of the real application against the workspace that
scripts/seed-workspace.py created.

Run seed-workspace.py first, then this.

Usage: python scripts/capture-screenshots.py
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

import websocket

BASE = "https://localhost:5230"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "images")
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 9333
WIDTH = 1440
SCALE = 2

CREDENTIALS = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".seed-credentials.json")

with open(CREDENTIALS, encoding="utf-8") as handle:
    creds = json.load(handle)


def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = struct.pack(">Q", int(time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


profile = tempfile.mkdtemp(prefix="keystead-shots-")
chrome = subprocess.Popen([
    CHROME,
    "--headless=new",
    f"--remote-debugging-port={PORT}",
    f"--user-data-dir={profile}",
    "--ignore-certificate-errors",
    "--allow-insecure-localhost",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--remote-allow-origins=*",
    f"--window-size={WIDTH},900",
    "about:blank",
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

ws_url = None
for _ in range(60):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=1) as r:
            tabs = json.load(r)
        page = next((t for t in tabs if t["type"] == "page"), None)
        if page:
            ws_url = page["webSocketDebuggerUrl"]
            break
    except Exception:
        pass
    time.sleep(0.5)

if not ws_url:
    print("chrome did not expose a page target")
    chrome.kill()
    sys.exit(1)

ws = websocket.create_connection(ws_url, timeout=60)
_id = [0]


def cdp(method, **params):
    _id[0] += 1
    mid = _id[0]
    ws.send(json.dumps({"id": mid, "method": method, "params": params}))
    while True:
        message = json.loads(ws.recv())
        if message.get("id") == mid:
            if "error" in message:
                raise RuntimeError(f"{method}: {message['error']}")
            return message.get("result", {})


def js(expression):
    result = cdp("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
    return result.get("result", {}).get("value")


def goto(url, settle=0.9):
    # A sentinel on the old document, because readyState is already "complete" before the
    # navigation commits: without this, goto returns on the page it was meant to leave. That
    # bit once already, when a second visit to a secret page kept the listeners the first
    # visit had attached and the reveal button both revealed and re-hid on one click.
    js("window.__keystead_before = 1")
    cdp("Page.navigate", url=url)

    for _ in range(100):
        if js("window.__keystead_before") is None and js("document.readyState") == "complete":
            break
        time.sleep(0.1)
    # Fonts decide the final layout, so a capture before they land measures the fallback.
    js("document.fonts && document.fonts.ready")
    time.sleep(settle)


def metrics(width, height):
    cdp("Emulation.setDeviceMetricsOverride",
        width=width, height=height, deviceScaleFactor=SCALE, mobile=False)


def shot(name, full=True, max_height=2600):
    height = 900
    if full:
        height = min(int(js(
            "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
        ) or 900), max_height)
    metrics(WIDTH, height)
    time.sleep(0.35)
    data = cdp("Page.captureScreenshot", format="png", captureBeyondViewport=False)["data"]
    path = os.path.join(OUT, name)
    with open(path, "wb") as handle:
        handle.write(base64.b64decode(data))
    print(f"  {name}  {WIDTH}x{height} @{SCALE}x  {os.path.getsize(path) // 1024} KB")
    metrics(WIDTH, 900)


cdp("Page.enable")
cdp("Runtime.enable")
cdp("Network.enable")
metrics(WIDTH, 900)

os.makedirs(OUT, exist_ok=True)

print("Signing in...")
goto(f"{BASE}/sign-in")
shot("01-sign-in.png", full=False)

js(f"""
(() => {{
  const f = document.querySelector('form');
  f.querySelector('input[type=email]').value = {json.dumps(creds['email'])};
  f.querySelector('input[type=password]').value = {json.dumps(creds['password'])};
  f.submit();
}})()
""")
time.sleep(2.5)

goto(f"{BASE}/sign-in/mfa", settle=0.4)
shot("02-two-factor.png", full=False)

# The enrolment consumed this window's code and the replay guard refuses a second use of it,
# so the first attempt may well be refused and the next window is waited for.
for attempt in range(3):
    code = totp(creds["totpSecret"])
    js("""
    (() => {
      const f = document.querySelector('form');
      f.querySelector('input[name="Input.Code"]').value = "%s";
      f.submit();
    })()
    """ % code)
    time.sleep(2.5)

    goto(f"{BASE}/", settle=0.3)

    if js("location.pathname") == "/":
        break

    wait = 31 - (int(time.time()) % 30)
    print(f"  code refused; waiting {wait}s for the next window")
    time.sleep(wait)
    goto(f"{BASE}/sign-in/mfa", settle=0.4)

landed = js("location.pathname")
print(f"  at {landed}")

if landed != "/":
    raise SystemExit("could not sign in; nothing past this point would be captured")

PAGES = [
    ("03-dashboard.png", "/", 2600),
    ("04-vaults.png", "/vaults", 1500),
    ("05-vault.png", "/vaults/production", 1500),
    ("07-audit.png", "/audit", 1700),
    ("08-members.png", "/members", 1500),
    ("09-identities.png", "/identities", 1200),
    ("10-security.png", "/security", 1000),
]

print("Capturing...")
for name, path, cap in PAGES:
    goto(BASE + path)
    shot(name, max_height=cap)

# The secret page, with the value showing. Step-up is already satisfied for this session only
# if it has been answered recently, so it is answered here the same way a person would.
print("Revealing a value...")
goto(f"{BASE}/vaults/production")
secret_url = js("""
(() => {
  const a = [...document.querySelectorAll('a[href*="/secrets/"]')]
    .find(x => x.textContent.includes('ConnectionStrings--Default'));
  return a ? a.getAttribute('href') : null;
})()
""")

if secret_url:
    # Masked first, before anything is clicked, so the hidden state is the one the page
    # actually loads in rather than one produced by clicking twice.
    goto(BASE + secret_url)
    shot("06-secret-hidden.png", max_height=1600)

    height = min(int(js(
        "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
    ) or 900), 1600)
    metrics(WIDTH, height)
    time.sleep(0.3)

    def reveal_and_wait():
        """Clicks reveal once and waits for the value to land. Returns whether it did."""
        js("document.querySelector('[data-reveal]').click()")

        for _ in range(40):
            if "step-up" in (js("location.pathname") or ""):
                return False

            shown = js("document.querySelector('[data-reveal-output]').textContent")

            if shown and not shown.startswith("•"):
                return True

            time.sleep(0.25)

        return False

    if not reveal_and_wait():
        # Step-up, answered the way a person would, then back to the page for one more click.
        js("""
        (() => {
          const f = document.querySelector('form');
          f.querySelector('input[type=password]').value = "%s";
          const c = f.querySelector('input[name="Input.Code"]');
          if (c) { c.value = "%s"; }
          f.submit();
        })()
        """ % (creds["password"], totp(creds["totpSecret"])))
        time.sleep(2.5)

        goto(BASE + secret_url)
        metrics(WIDTH, height)
        time.sleep(0.3)
        reveal_and_wait()

    shown = js("document.querySelector('[data-reveal-output]').textContent") or ""

    if shown.startswith("•"):
        print("  the value never appeared; capturing whatever is on screen")

    data = cdp("Page.captureScreenshot", format="png", captureBeyondViewport=False)["data"]
    with open(os.path.join(OUT, "06-secret-revealed.png"), "wb") as handle:
        handle.write(base64.b64decode(data))
    print(f"  06-secret-revealed.png  {WIDTH}x{height} @{SCALE}x")
    metrics(WIDTH, 900)
else:
    print("  could not find the secret link")

# The command palette, opened the way the shortcut opens it.
print("Command palette...")
goto(f"{BASE}/")
js("document.querySelector('[data-action=open-palette]').click()")
time.sleep(0.6)
js("""
(() => {
  const i = document.querySelector('[data-palette-input]');
  i.value = 'stripe';
  i.dispatchEvent(new Event('input', { bubbles: true }));
})()
""")
time.sleep(1.2)
shot("11-palette.png", full=False)

ws.close()
chrome.terminate()
try:
    chrome.wait(timeout=10)
except Exception:
    chrome.kill()
shutil.rmtree(profile, ignore_errors=True)
print("done")
