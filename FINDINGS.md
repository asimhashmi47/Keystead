# Findings

What happened when the application was run, measured and attacked rather than read. Three
passes: a quality pass that drove every page in a browser, a load pass that put a thousand
concurrent callers through it, and an adversarial pass that tried to break the things it
promises.

Everything here is a measurement or a request that was actually made. Where a number appears,
the command that produced it is named. Where something was not established, it says so.

- [What was fixed](#what-was-fixed)
- [What the load test found](#what-the-load-test-found)
- [What the adversarial pass found](#what-the-adversarial-pass-found)
- [What fixing the findings turned up](#what-fixing-the-findings-turned-up)
- [The finding that was accepted rather than fixed](#the-finding-that-was-accepted-rather-than-fixed)
- [Scope of improvement](#scope-of-improvement)

---

## What was fixed

Four defects that only appear when the application runs. None of them would fail a build, a
test or a code review, and all four were plainly visible within a minute of opening the thing
in a browser and watching what it did.

### 1. Every inline style in the markup was discarded by the browser

**What it was.** The policy is `style-src 'self' 'nonce-...'` with no `'unsafe-inline'`. A
`style` attribute cannot carry a nonce, so the browser refused all fifty-six of them. The
console carried a violation for each one; the pages rendered with margins, alignment and widths
quietly missing.

**Why it matters beyond the cosmetic.** A policy nobody had exercised against the markup was
being described in the README as a security property. It was a real policy doing real work —
and the first thing it blocked was the application's own interface. That is the sort of finding
that gets "fixed" by adding `'unsafe-inline'`, which would have thrown away the protection to
straighten a margin.

**Fixed by** moving the declarations into the stylesheet as a small, closed utility layer, and
adding `ThereAreNoInlineStyleAttributes` to the source rule suite so one cannot come back.

### 2. The self-hosted font was never in the repository

The stylesheet asked for `/fonts/inter-variable.woff2`. There was no `fonts` directory. Every
page 404'd on it and rendered in whatever the platform offered, while the README said the
product self-hosts a variable font.

**Fixed by** vendoring Mona Sans and Mona Sans Mono under the SIL Open Font Licence they ship
with, and adding `TheSelfHostedFontsArePresent`, which fails if the stylesheet names a font file
that is not there.

### 3. Every request ran an Argon2id hash it did not need

This is the significant one.

`SignInService` computed its decoy digest in its constructor. The decoy is the digest verified
against when no account matches the submitted address, so that an unknown address costs the same
as a known one — a good control, correctly reasoned, in the wrong place. The service is
registered **scoped**, so the constructor ran on every request that injected it, and the
authenticated cookie validator injects it on every authenticated request.

That meant a full Argon2id hash — 64 MiB of memory and about a third of a second — on every
page view in the application, including an anonymous `GET` of the sign-in form, which otherwise
does no work at all.

Measured, before and after, with the same eight-sample warm loop:

| Page | Before | After |
|---|---|---|
| `/sign-in` (anonymous) | 313 ms | 15 ms |
| `/sign-out` | 402 ms | 17 ms |
| `/` (dashboard) | 350 ms | 23 ms |
| `/vaults` | 354 ms | 15 ms |
| `/members` | 360 ms | 13 ms |
| `/forbidden` (injects nothing) | 18 ms | 18 ms |

The last row is the control: a page that injects no services was always fast, which is what
localised the cost.

**It was also a denial-of-service primitive.** An unauthenticated request to a public page
spent 64 MiB and a third of a second of someone else's server. The sign-in limiter capped that
at ten per address per five minutes, but ten addresses are not expensive to come by.

**Fixed by** computing the decoy once per process, on first use. The verification work at
authentication time is unchanged, which is the part the control depends on; the digest's
plaintext is random and discarded, so a value fixed for the process lifetime tells an attacker
exactly as much as a fresh one, which is nothing.

### 4. The sign-in rate limit counted page views

`[EnableRateLimiting("sign-in")]` on a Razor page covers **every handler on that page**, so the
`GET` that renders the form was counted against the same ten-attempt budget as the `POST` that
submits it. Ten views in five minutes — a few reloads, a browser prefetch, a password manager
opening the page — spent the budget, and the sign-in that followed was refused with a 429.

This was found by being locked out of the application while benchmarking it.

It is worth separating from the others because it *looks like the control working*. The log
shows a 429 on a sign-in path; everything reads as intended. What is actually happening is a
denial of service against the user by a control aimed at the attacker.

**Fixed by** having the policy return no limiter for safe methods, so it counts submissions.
The global limiter still covers the page itself. `RateLimitTests` asserts that twenty-five
consecutive views of the sign-in form are never refused.

### Also fixed along the way

- **`[hidden]` did not hide anything.** The user agent's `[hidden] { display: none }` loses to
  any author rule, so `.btn { display: inline-flex }` quietly un-hid the Copy button next to a
  masked secret. Copying a masked value does nothing useful.
- **The sidebar scrolled sideways** and truncated the signed-in address mid-word. The account
  moved into the top bar, where there was a large empty space and no account control.
- **A page entrance animation was removed** rather than kept. Animating content in means it
  starts at `opacity: 0` and depends on the animation clock to become visible. In a background
  tab that clock is throttled, and the page rendered half-faded — reproduced while capturing
  screenshots. For a tool someone keeps open in a tab all day, that is a real failure bought
  for a flourish nobody asked for.
- **Stale copy** in the service identity page still said the SDK was a future milestone.

---

## What the load test found

`scripts/load-test.py`, against a release build on one machine. Three scenarios: a thousand
applications fetching a secret by name over the machine API, a thousand concurrent dashboard
loads from signed-in browsers, and three hundred concurrent writes through the audit chain.

### The headline

**Nothing broke.** Across every run — 3,000 dashboard loads at 600 concurrent in the widest
test — there were **zero 5xx responses, zero dropped connections and zero corrupted state**. The
audit chain verified clean afterwards. Under the shipped limits the application sheds load with
429s and keeps serving; with the limits raised it serves everything.

### The rate limiter is the first thing you hit, and that is partly wrong

With the shipped defaults, 872 of 1,000 machine reads were refused with a 429 — while eight
*distinct* service identities were in use. The limiter partitions authenticated traffic by
principal and everything else by remote address, and the machine API resolves its bearer token
**inside the endpoint**, after the limiter has already run. So `context.User` is anonymous at
partition time and every machine caller from one address shares one bucket.

For an installation behind a load balancer, a NAT gateway or inside a corporate network, that
means every application shares a single budget and one chatty service starves the rest.

**Fixed, in two steps.** The limits became configurable (`Keystead:RateLimits`), because an
operator in that position previously had no way to raise them at all — and then the partition
key itself was changed, which is what actually solved it. The same scenario now runs clean on
the shipped defaults: see [F1](#f1---machine-api-rate-limiting-was-keyed-by-source-address-not-by-identity).

### The ceiling that was found is the harness, not the application

With the limits raised, throughput settled at roughly 40 requests a second from one client and
68 from three clients in parallel. That looks like a server ceiling. It is not.

Serilog's own request durations, taken from the same run at 600 concurrent:

| | Client observed | Server observed |
|---|---|---|
| p50 | 6,256 ms | 54.7 ms |
| p95 | 21,005 ms | 115.2 ms |
| p99 | 32,263 ms | — |
| max | 36,155 ms | 192.4 ms |

The server handled each dashboard load in 55 ms median and 192 ms at worst, on an eight-core
machine that stayed mostly idle. The multi-second latencies are queueing in the Python client
and the loopback TLS path, not in the application.

**So the honest statement is: this harness did not find the application's ceiling. It found its
own.** Establishing the real ceiling needs a purpose-built load generator on a separate machine.
What *was* established is that at 600 concurrent callers the application's own work stays under
200 ms and nothing fails.

### A per-request write that did not need to be one

Every authenticated request wrote `LastSeenUtc` to the session row. On a store that takes one
writer at a time, making every page view a write is the kind of thing that becomes the ceiling
as soon as a real ceiling exists. It was not the current bottleneck — removing it did not move
the numbers — but it was wrong on its own terms.

**Fixed by** writing the timestamp only when it has moved by more than `LastSeenPrecision`
(default one minute). The idle timeout is measured in tens of minutes, so a minute of
granularity is not a difference anyone can perceive.

---

## What the adversarial pass found

`scripts/pentest-probe.py` makes twenty-one real attempts against a running instance. All
twenty-one were refused.

| Area | Attempt | Result |
|---|---|---|
| Access | Every authenticated page, unauthenticated | Redirected to sign-in |
| Cookies | Flags on `__Host-` cookies | `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` |
| Enumeration | Known vs unknown address, timed | 370 ms vs 390 ms over three samples each |
| CSRF | `POST` with a valid session, no token | 400 |
| CSRF | `POST` with a forged token | 400 |
| Redirect | Four off-site `next=` candidates | All refused or ignored |
| Exposure | Secret value in the detail page markup | Not present |
| Exposure | Reveal handler by `GET` | No value returned |
| Authz | Vault the identity was not granted | 404 |
| Authz | Vault that does not exist | 404 |
| Tokens | Re-signed with `alg=none` | 401 |
| Tokens | Edited subject, original signature | 401 |
| Tokens | Replaced signature | 401 |
| Tokens | No token at all | 401 |
| Revocation | Token held by an identity revoked a moment ago | 401 |
| Injection | `<script>` stored as a secret name | Rendered encoded |
| Injection | Path traversal in a secret name | 404 |
| Injection | Quote in a secret name | 404 |
| Escalation | `Input.Role=Owner` posted alongside an invitation | Ignored; owner count unchanged |
| Audit | Chain verification | Verified |

Two notes on method, because a probe that lies in your favour is worse than no probe.

The first run reported three failures. All three were defects in the probe, not the
application: the cookie check was case-sensitive against attribute names the framework emits in
lower case; the timing comparison took one sample each way, and the unknown address happened to
pay for the one-off lazy decoy computation; and the revocation probe revoked the last identity
on the page rather than the one it held a token for. Each is written up in the script.

The revocation result is worth calling out as a genuine strength: `TokenIssuer.ValidateAsync`
re-reads the identity on **every** call, so revoking a service identity takes effect on the next
request rather than when its token expires. Most implementations of this shape do not.

**What this pass does not cover:** the cryptography, which is tested where it lives; anything
needing more than one workspace with real users in each; timing attacks at a resolution a
network can resolve; and the deployment itself. It is a probe, not a review.

---

## What fixing the findings turned up

The adversarial pass listed six findings and fixed none of them, deliberately: an attack that
has just succeeded is the worst possible moment to design the answer to it. Five were then
worked through properly. One was accepted as designed behaviour and is set out in the next
section.

Two of the five turned out to be worse than the write-up said, which is the recurring lesson of
this whole exercise: a finding reached by reading the code describes what the code says, and
only running it says what it does.

### F1 - Machine API rate limiting was keyed by source address, not by identity

**What it was.** The limiter partitioned authenticated traffic by principal and everything else
by remote address, and the machine API resolves its bearer token *inside* the endpoint, after
the limiter has run. So at partition time every machine caller was anonymous, and every service
identity arriving from one address shared one bucket. Behind a load balancer or a NAT gateway
that is every application in the estate on one budget, and the symptom - a 429 on a correctly
credentialled request - looks like the caller's fault.

**Measured, on the shipped defaults, eight distinct service identities from one address:**

| | Before | After |
|---|---|---|
| Refused with 429 | 872 of 1,000 | **0 of 1,000** |
| Served | 128 | 750, plus 250 deliberate misses answered 404 |

**Fixed by** partitioning per caller instead: the signed-in principal, or - when the request
presents a bearer token the limiter has not yet verified - a truncated SHA-256 of that token.
The token itself is never the key, because a partition key reaches logs, metrics and
diagnostics and the token is a live credential.

**The part that needed thinking about.** A key derived from an unverified credential is one an
attacker can fabricate, so rotating tokens would mint a fresh bucket per request. That is why
the global limiter is now a *chain* of two: an inner per-caller window for fairness, and an
outer per-address window as the boundary, keyed by something the client cannot choose. The
per-caller key groups requests; it never admits them. A fabricated token still fails at the
endpoint with a 401 before it reaches a vault.

Verified by attacking it: 400 requests from one address, each carrying a freshly fabricated
token, against a per-address ceiling of 200 - **199 served, 201 refused**. The per-caller
limiter cannot see those as one caller. The address limiter can.

### F2 - The reverse proxy configuration was never applied at all

This is the one that was worse than the finding.

**What the finding said.** `Keystead:ReverseProxy` binds straight onto
`ForwardedHeadersOptions`, so an operator could widen `KnownNetworks` to `0.0.0.0/0` in one
line of JSON and hand every client the ability to forge its own address.

**What was actually true.** They could not widen it, because they could not set it. The
configuration binder populates a scalar such as `ForwardLimit` and **cannot construct an
`IPNetwork` or an `IPAddress` from a string**, so every network and every proxy an operator
named was discarded in silence. Confirmed directly, binding the documented configuration into a
fresh options object:

```text
ForwardLimit    = 2                 <- bound
KnownIPNetworks = 127.0.0.0/8       <- the default; "172.16.0.0/12" was dropped
KnownProxies    = ::1               <- the default; "10.0.0.5" was dropped
```

So any installation behind a proxy - which is every production installation, since the product
requires TLS it does not terminate itself - trusted loopback only, ignored `X-Forwarded-For`,
and saw the proxy as every client. The IP allowlist on a service identity compared the proxy's
address rather than the caller's. The per-address rate limit treated the entire internet as one
client. `DEPLOYMENT.md` documented the setting that fixes exactly that, and it did nothing.

Nothing about a running installation looked wrong. The security centre showed an allowlist. The
limiter showed 429s.

**Fixed by** owning the strings: `ReverseProxyOptions` binds plain text, and the parse,
validation and application are deliberate code with tests either side of them. Naming a proxy
now replaces the loopback default rather than adding to it, so a sibling container on the host
cannot still choose its own address.

**Measured**, with the proxy named and a per-address ceiling of 60: 100 requests carrying 100
distinct forwarded addresses, **all 100 served**. Before, all 100 shared the one bucket the
connection came from.

And the original footgun is closed on the way past. A range wide enough to cover any client
stops the process at startup unless an operator says, in as many words, that every connection
terminates at a proxy that overwrites the header:

```text
KnownNetworks entry '0.0.0.0/0' is wide enough that any client could choose the address
Keystead sees, which defeats the per-address rate limits and the IP allowlist on service
identities. Name the proxy's own network, or set
Keystead:ReverseProxy:TrustAnyProxyAddress to true if every connection really does
terminate at a proxy that overwrites X-Forwarded-For.
```

An unparseable entry stops it too, acknowledged or not. A typo is never a decision, and
treating one as a decision is what caused this in the first place.

### F4 - Step-up returned to a dead end

**What it was.** Revealing a value without a fresh step-up redirected to the confirmation form,
correctly - and then returned the browser to `?handler=Reveal` as a `GET`, which renders the
page with the value still hidden. The person typed their password, typed their code, and
watched nothing happen.

Not a vulnerability. It is how people learn to click through authentication prompts, which
eventually is one.

**Fixed by** having the return URL carry the intent rather than the handler, and having the page
act on it. The marker is a request to retry the reveal, not an authorisation to perform one: the
step-up decides that, and the `POST` handler is still the only thing that can return a value. It
is consumed before the request goes out, so a reload or a shared URL cannot silently repeat an
audited read.

**Verified in a browser**, against a session whose step-up had been backdated past the window:
clicking reveal lands on `/step-up?next=%2Fvaults%2Fproduction%2Fsecrets%2F...%3Freveal%3D1`,
confirming returns to the clean page URL, and the value appears with *Showing version 4. This
read has been recorded.* No second click.

**And a bug found while fixing it.** The reveal button's click handler was registered with
`{ once: true }`. After any refusal - a stale step-up, a disabled secret - the listener was
gone, so the button looked enabled and did nothing until the page was reloaded. It now holds
one listener for the life of the page and switches on what is on screen.

### F5 - `no-store` was applied to static assets too

**What it was.** The security headers middleware set `Cache-Control: no-store` on every
response, including the stylesheet, the scripts and a 137 KB font. Correct and important for
anything that may carry secret material, and pure waste for files that carry none - re-fetched
on every page load of a tool people keep open all day.

**Fixed by** exempting the asset tree, written in the direction that stays correct: `no-store`
is the default, and the exemption is a closed list of path prefixes. A new page is covered
automatically; a new asset directory has to be named where the decision is visible. The URLs
carry a content hash, so a year-long immutable lifetime cannot serve a stale file, and a source
rule fails the build if an asset is referenced without one.

Live, after the change:

| Path | `Cache-Control` |
|---|---|
| `/css/keystead.css` | `public, max-age=31536000, immutable` |
| `/fonts/keystead-sans.woff2` | `public, max-age=31536000, immutable` |
| `/js/reveal.js` | `public, max-age=31536000, immutable` |
| `/sign-in` | `no-store, no-cache, must-revalidate, max-age=0` |

### F6 - Session fixation across the second factor was not proven

**What it was.** Nothing was wrong. The flow was already right: a separate short-lived scheme
carries the pending user id between the password step and the code step, no session row exists
until both factors are in, and the identifier is a fresh value minted server-side on
completion. What was missing was anything that said so, which is the only reason a correct
implementation stays correct through the next change.

**Fixed by** five tests that state it: the password step alone creates no session, a wrong
second factor creates none, the session appears only after the second factor succeeds, two
completed sign-ins never share an identifier, and the new session starts with its step-up set
by the server rather than by anything a client sent.

### Confirmed afterwards

- `dotnet build` - 0 warnings, 0 errors. `dotnet format --verify-no-changes` - clean.
- **603 tests pass**: 466 unit, 25 integration, 112 security.
- The adversarial pass was re-run against the changed pipeline: **21 of 21 attacks still
  refused**.

---

## The finding that was accepted rather than fixed

### F3 - The audit chain converts write contention into failed actions

Appending is `SELECT MAX(seq)` then `INSERT`, guarded by a process-wide semaphore, with a
unique index as the real protection and five retries on violation. Two consequences follow:

- The semaphore does nothing across processes. In a multi-process deployment the retry loop is
  the only thing holding the line.
- When five retries are exhausted the action **fails**.

That second one is the behaviour, and it is deliberate. An action that happened without an
audit entry is worse than an action that did not happen, so the failure direction is correct.
What it means in practice is that sustained write contention presents as user-visible errors
rather than as slowness, and that is worth knowing before it is discovered.

It was not reached under load: three hundred concurrent writes all succeeded and the chain
verified afterwards.

Changing it would mean a single-writer queue with an explicit depth and a stated backpressure
policy, so contention becomes a measured wait instead of a retry budget. That is a design
decision about how the product behaves when it is overloaded, not a defect to patch, and it
belongs with the work in the next section rather than in a fix made under the pressure of a
finding.

---

## Scope of improvement

The six findings are dealt with above. What follows is everything else, roughly ordered by
what would matter most to someone actually running this.

### Security

1. **A single-writer queue for the audit chain** (F3), so overload becomes a measured wait
   rather than a retry budget and a failed action.
2. **Key rotation for the master key.** Vault KEKs and data keys rotate; the master key does
   not. A compromised master key currently means re-encrypting by hand.
3. **Break-glass access.** If the only owner loses their authenticator and their recovery codes,
   the workspace is unreachable. That is defensible, but it should be a documented decision
   rather than an emergent one.
4. **Secret scanning on write.** A connection string pasted into the name field, or a value that
   is obviously a private key where a password was expected, could be caught at the door.
5. **Per-identity rate limits as policy.** The limiter now gives each service identity its own
   budget; it does not yet let an operator set a *different* budget for a particular identity,
   which is what a known-chatty deployment actually needs.

### Correctness and operations

6. **A real load generator on separate hardware**, so the application's actual ceiling is known
   rather than the harness's.
7. **Backup and restore as a tested path.** `DEPLOYMENT.md` describes it; nothing exercises it.
   A backup nobody has restored is not a backup.
8. **Postgres as an alternative store.** SQLite is the right default for one box and the wrong
   answer for two. The EF model is portable; the pragma interceptor and the audit append are
   what would need attention.
9. **Structured health detail.** `/healthz` returns a bare 200. It could report master key
   readiness, migration state and chain verification separately.
10. **A startup check that the forwarded-headers configuration is reachable.** The parse is
    validated now, but nothing tells an operator that the proxy in front of them is connecting
    from an address they did not name - which is the failure F2 hid for so long, in a different
    disguise.

### Interface

11. **The members page is doing too much.** A role select, a two-factor state, grant chips and a
    grant form on every row, in a table that needs a horizontal scrollbar at 1440 px. It wants
    to be a detail panel.
12. **Empty states.** A new workspace lands on a dashboard of zeroes with nothing suggesting
    what to do first.
13. **Bulk operations.** Rotating twelve secrets means twelve round trips through the interface.
14. **Device summaries in the security centre.** It renders the raw user agent string, which
    wraps across two lines and tells nobody anything.

### Accessibility

15. The contrast ratios, focus rings and keyboard reachability are implemented and asserted in
    `Keystead.SecurityTests`, but have never been put in front of a screen reader. That is a
    different kind of verification and the claim should not be made until it has been done.
