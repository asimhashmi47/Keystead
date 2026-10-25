# Keystead

A self-hostable secrets manager for developers and small teams. A central place to keep API
keys, connection strings, certificates and tokens — and a way for applications to fetch them at
runtime by name, so nobody has to paste a connection string into a chat window again.

Built on .NET 10, ASP.NET Core Razor Pages, EF Core and SQLite. Concept-comparable to Azure Key
Vault, scoped to something a small team can actually run on one box.

![The dashboard](images/03-dashboard.png)

---

## What it does

**For people.** Sign in with a password and a second factor, group secrets into vaults, store
and version values, and reveal one when you need it — masked by default, behind a re-confirmed
identity, recorded in the audit log, hidden again after thirty seconds.

**For applications.** A service identity authenticates with client credentials, receives a
short-lived ES256 token scoped to the vaults it was granted, and reads secrets by name. The
.NET SDK makes that a single line in `Program.cs`; the CLI injects secrets into a child process
without them ever touching a file.

```csharp
builder.Configuration.AddKeystead(options =>
{
    options.Endpoint = new Uri("https://keystead.internal");
    options.ClientId = "orders-api-prod";
    options.ClientSecret = builder.Configuration["KEYSTEAD_CLIENT_SECRET"]!;
});

// A secret stored as ConnectionStrings--Default is read the way any other setting is.
var connection = builder.Configuration.GetConnectionString("Default");
```

```bash
keystead run --vault production -- dotnet MyApp.dll
```

---

## How it looks

Every screenshot is of the running application, captured by
[`scripts/capture-screenshots.py`](scripts/capture-screenshots.py) against the workspace that
[`scripts/seed-workspace.py`](scripts/seed-workspace.py) creates. Nothing is mocked up.

### Signing in

Two factors, always. An account with administrative rights cannot complete sign-in until it has
enrolled a second factor — not a prompt it can dismiss.

| | |
|---|---|
| ![Sign in](images/01-sign-in.png) | ![Two-factor code](images/02-two-factor.png) |

### Vaults and secrets

A vault groups secrets that belong together and holds its own encryption key, so access and key
rotation are scoped to it rather than to the whole workspace.

![Vaults](images/04-vaults.png)

![A vault](images/05-vault.png)

Every table in the product works the same way: search across the columns, a filter per column,
a sort on anything that can carry one, and a download as a workbook or as CSV. All of it lives
in the URL, so a filtered view is a link.

![A vault, filtered by environment](images/05b-vault-filtered.png)

### Revealing a value

The value is never in the page markup. Revealing it is a `POST` with an antiforgery token
behind a re-confirmed identity; the response carries `Cache-Control: no-store`, the read is
written to the audit log, and the value hides itself again after thirty seconds.

| Masked by default | After confirming identity |
|---|---|
| ![A secret, masked](images/06-secret-hidden.png) | ![A secret, revealed](images/06-secret-revealed.png) |

Storing a new value appends a version rather than overwriting one. Rolling back re-seals the
old value as a *new* version, so history stays append-only and the rollback is itself auditable
and reversible.

### The audit log

Every read, write, sign-in, permission change and refusal, in order. Each entry commits to the
one before it over a length-prefixed canonical encoding, so an entry cannot be altered,
inserted or removed without verification failing — and the page verifies the chain on load.

![The audit log](images/07-audit.png)

### Members and service identities

People get a role and, optionally, grants on individual vaults. Applications get their own
identity with its own credentials, its own vault scope, an optional IP allowlist, and rotation
with an overlap window so a deploy does not have to be atomic.

![Members](images/08-members.png)

Choosing a person opens their panel: role, two-factor state, the vaults they can open, and the
way out. The list answers who is here; the panel answers what one person can do.

![A member's access](images/08b-member-detail.png)

![Service identities](images/09-identities.png)

### Security centre and command palette

Where you are signed in, from what, and how to end any of it. And `Ctrl`+`K` from anywhere.

| | |
|---|---|
| ![Security centre](images/10-security.png) | ![Command palette](images/11-palette.png) |

---

## Why the design looks like this

**Envelope encryption, three tiers.** A master key wraps a per-vault key-encryption key, which
wraps a per-version data-encryption key, which seals the secret value. The master key never
lives in the database, so a stolen database file is not a stolen secret.

**Every ciphertext is bound to its row.** AES-GCM additional authenticated data covers the
workspace, vault, secret, version, purpose and key generation. This closes a specific attack:
someone with database write access but no key could otherwise copy the ciphertext of a secret
they are allowed to read into the row of one they are not, and the server would decrypt it
happily. With binding, relocation produces a tag mismatch instead.

**Random nonces, never a counter.** A counter makes reuse impossible within one process, and
that is the problem: the same database can be served by several processes, restored from a
backup, or replicated, and any of those resets it. Nonce reuse under one key is catastrophic
for GCM, so every seal draws 96 fresh random bits.

**The audit log is a hash chain.** Each entry commits to the one before it, over a
length-prefixed canonical encoding. Length prefixes rather than delimiters, so two different
entries cannot serialise to identical bytes. An insider with database write access can still
rewrite rows; they cannot do it without verification failing.

**Deny by default.** The authorization fallback policy requires an authenticated principal, so
an endpoint that forgets to declare a policy fails closed rather than open.

**Revocation bites immediately.** Token validation re-reads the service identity on every call,
so revoking one takes effect on the next request rather than when its token happens to expire.

---

## What is here

| Area | What exists |
|---|---|
| Solution | 9 projects in Clean Architecture order; Central Package Management; `nullable`; warnings as errors; CA security rules at *error* |
| Cryptography | AES-256-GCM AEAD primitive; `CryptoContext` AAD binding; `KeyMaterial` with zeroing; three master key providers (environment, mounted file, DPAPI / 0600 file) |
| Passwords | Argon2id at 64 MiB / t=3 / p=1, per-user salt, optional pepper, PHC-encoded digests, rehash-on-upgrade |
| Audit | Tamper-evident hash chain with canonical encoding and verification |
| Persistence | Full 14-table schema, EF migration applied and checked, 36 indexes, SQLite pragmas (WAL, `foreign_keys`, busy timeout) per connection |
| Web hardening | Strict nonce CSP from `default-src 'none'`; full header set; `no-store`; no `Server` banner; antiforgery global; configurable rate-limit policies; Kestrel limits |
| Interface | Design system in plain CSS with semantic tokens; self-hosted variable font; persistent sidebar on every authenticated page; progressive-enhancement JS modules, no inline script, no inline style, no CDN |
| Identity | Argon2id sign-in with decoy-hash enumeration resistance; progressive lockout; TOTP with single-use replay guard; 10 single-use recovery codes; server-validated sessions with revocation |
| RBAC | Role/capability matrix as pure domain logic; vault grants with a role ceiling; workspace scoping and authorization checked separately on every call; step-up re-authentication |
| Setup | First-run wizard that closes permanently once an account exists; recovery kit with the master key fingerprint shown once |
| Vaults | Create, list, soft delete, recover, purge; per-vault key created with the vault; recovery window and purge protection enforced |
| Secrets | Append-only versions, enable/disable, soft delete and recover, expiry and rotation reminders, tags, environment scoping |
| Reveal | Masked by default, never in the page markup, fetched by `POST` with an antiforgery token, step-up required, `no-store`, auto-hides after 30 seconds |
| Rollback | Re-seals the old value as a new version rather than reviving the old row, so history stays append-only and the rollback is itself auditable |
| Audit viewer | Filterable log with a chain-verification badge and a CSV export guarded against spreadsheet formula injection |
| Service identities | Client secrets with a checksum, stored as SHA-256, shown once; rotation with an overlap window; per-identity IP allowlist; revocation that bites on the next call |
| Machine API | OAuth2 client credentials to a short-lived ES256 token with a rotatable signing key; scoped per vault; RFC 7807 problem documents; ETag revalidation; `no-store` throughout |
| Members | Roles and per-user vault grants, with the last-owner rule and no self-promotion to owner; new accounts get a one-time password shown once |
| Profile | Change your own password (revoking every other session) and replace a lost authenticator using a recovery code |
| Search and palette | Name search across reachable vaults and secrets, and a `Ctrl`+`K` command palette built on `<dialog>` so focus trapping and Escape come from the platform |
| SDK | `builder.Configuration.AddKeystead(...)` with token caching, retry, optional polling reload, and `--`/`__` to `:` key mapping, so application code never mentions Keystead |
| CLI | `keystead secret list/get/set`, `env`, and `run -- <command>` which injects secrets into a child process and propagates its exit code |
| Packaging | Chiselled non-root image, read-only root filesystem, all capabilities dropped, mounted master key, plus Caddy and Nginx reverse proxy configs |
| CI | Build with warnings as errors, `dotnet format` gate, coverage report, CodeQL at security-and-quality, CycloneDX SBOM, Dependabot, and a container build that asserts a non-root user |

---

## How it is verified

**715 tests, all passing** — 569 unit, 25 integration, 121 security.

The failure cases carry the weight: tamper on ciphertext, nonce and tag; wrong key; ciphertext
moved to another workspace, vault, secret or version; purpose confusion; nonce uniqueness across
200 seals; malformed and weaker-parameter password digests; pepper mismatch; audit chain edit,
rehash, delete and reorder detection; the full role matrix checked exhaustively; TOTP replay and
seed relocation; cross-tenant access attempted from six directions and refused each time; and
the full three-tier envelope with a value relocated to another workspace, vault, secret and
version, a data key spliced in from a different version, and a value presented as its own
wrapped key.

The token suite performs the classic JWT attacks and asserts each is refused: `alg: none`,
HS256 confusion (signing with the public key as an HMAC secret), a token signed by an attacker's
key claiming the server's key id, a tampered signature, a token with no key id, an expired
token, and a token held by an identity that has since been revoked.

**Security claims are tests, not comments.** Every header, cookie flag and CSP directive this
README promises has an assertion in `Keystead.SecurityTests`, run against the real pipeline as
`Program` composes it. A set of source rules enforces the absolutes that no runtime test can
reach: no `Html.Raw`, no inline script, no inline style, no inline event handler, no `eval`, no
`innerHTML`, no CDN, no concatenated SQL, no weak primitive, no cipher mode but GCM, no
equality operator on secret-derived bytes, and no unfinished placeholder in any file that
touches a key.

### Against a running instance

Four scripts drive the real application over HTTP rather than in-process:

| Script | What it does |
|---|---|
| [`seed-workspace.py`](scripts/seed-workspace.py) | Builds a realistic installation — four vaults, sixteen secrets, six members, four service identities, version history and a rollback — entirely through the public interface |
| [`smoke-flow.py`](scripts/smoke-flow.py) | 81 assertions over the whole flow, including that a secret value appears in no list page, no detail page, no browser `GET`, no API list response, no audit row and no CSV export |
| [`verify-sdk-cli.py`](scripts/verify-sdk-cli.py) | 29 more against the SDK, the CLI and the OpenAPI document |
| [`pentest-probe.py`](scripts/pentest-probe.py) | 21 real attacks — forged tokens, `alg: none`, cross-vault reads, CSRF, open redirects, path traversal, stored script, mass assignment — each of which must be refused |
| [`load-test.py`](scripts/load-test.py) | A thousand concurrent callers through three scenarios, counting outcomes by status so a 429 is read as the limiter working rather than as a failure |

### What that turned up

Running and measuring the application found four defects that no build, test or review had:
every inline style silently discarded by the Content Security Policy, a self-hosted font that
was never in the repository, a full Argon2id hash on every request including anonymous ones,
and a rate limit that counted page views and locked users out of signing in.

Attacking it found six more. Two of those were worse than the first write-up of them: the
machine API's rate limits were keyed by source address, so eight service identities behind one
address shared one budget and 872 of a thousand reads were refused; and the reverse proxy
configuration an operator writes was **never applied at all**, because the configuration binder
cannot turn `"172.16.0.0/12"` into an `IPNetwork` and dropped it in silence. The second one
meant any installation behind a proxy compared the proxy's address against a service identity's
IP allowlist, and treated every caller on the internet as one client for rate limiting, while
the security centre carried on showing an allowlist.

Those are fixed and measured, as is the step-up flow that used to return people to a page where
nothing had visibly happened, and the `no-store` that was being applied to the font as well as
to the secrets. One finding is accepted as designed behaviour and written down rather than
patched: the audit chain fails an action rather than lose an entry.

Every measurement, the load test results, the twenty one attack attempts, the before-and-after
numbers, and the scope of improvement are in **[FINDINGS.md](FINDINGS.md)**.

### Every table is the same table

Members, vaults, the secrets in a vault, service identities, sessions and the audit log are all
rendered by one engine and one set of partials, so each of them has free-text search across its
columns, a filter per column, a sort on every column that can carry one, paging, and a download
as a real `.xlsx` workbook or as CSV.

Four decisions worth stating, because each one was the alternative to something easier:

- **A column is declared once.** The same declaration is the header, the filter, the sort key
  and the export column. Writing those separately is how a spreadsheet quietly stops matching
  the screen it was taken from.
- **The state is the URL.** Search, filters, sort, page and the open detail panel all travel in
  the query string, so a filtered view is a link someone can send. Nothing is kept in the
  browser that the server does not already know.
- **It works with scripting blocked.** The toolbar is a GET form with an Apply button, sorts and
  pages are links, and the per-column filter row opens with a query value. The script removes a
  click; it never adds a capability.
- **The workbook is a workbook.** Not a CSV with the extension changed, which Excel offers to
  repair. Every cell is an inline string, which is also why the file cannot carry a formula: an
  exported audit log holds user agents that a caller chose, and it is the file a reviewer opens.

The members page is a list beside a panel rather than a table carrying five controls on every
row. A table that needs a horizontal scrollbar at 1440 px is a table that has been asked to do
two jobs.

### Known gaps

There is no JWKS endpoint — the public keys are stored and usable but not published. Master-key
and vault KEK rotation are modelled and stored but have no background job to run them; token
signing key rotation is implemented and tested. Revealing a secret and the command palette both
require JavaScript; every other action, including search, works without it. See
[TRACEABILITY.md](TRACEABILITY.md) for every requirement mapped to its implementation and test,
or to the reason it is absent.

---

## Running it

Requires the .NET 10 SDK.

Generate a master key and export it:

```bash
export KEYSTEAD_MASTER_KEY=$(openssl rand -base64 32)
```

Apply the schema and start the application:

```bash
dotnet ef database update --project src/Keystead.Infrastructure && dotnet run --project src/Keystead.Web
```

Open the application and the first-run wizard creates the workspace and the owner account. The
wizard closes permanently once an account exists.

The application **refuses to start** without a valid 256-bit master key. That is deliberate:
starting without one would give you a process that looks healthy, accepts writes, and cannot
decrypt anything it stored.

Run the tests:

```bash
dotnet test
```

To fill a local instance with something to look at:

```bash
python scripts/seed-workspace.py https://localhost:5001
```

---

## Repository layout

```
src/Keystead.Domain          entities and domain rules; references nothing
src/Keystead.Application     use cases and ports (IClock, IAeadCipher, IMasterKeyProvider)
src/Keystead.Infrastructure  EF Core, cryptography, key providers, migrations
src/Keystead.Web             Razor Pages UI and the machine API under /api/v1
src/Keystead.Client          SDK and the AddKeystead() configuration provider
src/Keystead.Cli             the `keystead` dotnet tool
tests/Keystead.Tests              unit tests (crypto, hashing, audit chain, identity)
tests/Keystead.IntegrationTests   WebApplicationFactory suites over the whole flow
tests/Keystead.SecurityTests      headers, CSP, cookie flags, rate limits, source rules
scripts/                          seeding, screenshots, smoke flow, load test, attack probe
```

### Documents

| File | What it is for |
|---|---|
| [FINDINGS.md](FINDINGS.md) | What running, measuring and attacking it turned up, what was fixed, and what was accepted instead |
| [CLAUDE.md](CLAUDE.md) | The conventions and non-negotiable security rules for any change here |
| [PLAN.md](PLAN.md) | The design and the milestone plan |
| [THREATMODEL.md](THREATMODEL.md) | STRIDE table, and a limitations section that is not a formality |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, and what is in scope |
| [DEPLOYMENT.md](DEPLOYMENT.md) | How to run it, ordered by what breaks worst if you get it wrong |
| [TRACEABILITY.md](TRACEABILITY.md) | Every requirement mapped to its implementation and test, or to why it is absent |

---

## A note on what the cryptography here does and does not do

`KeyMaterial` zeroes key bytes on disposal, which bounds how long a key sits in memory. It does
not guarantee the key was never copied: the CLR may relocate an array during a compacting
collection, and nothing in managed code defends against a memory dump taken while a key is
live. That is a real limit, recorded here rather than hidden, and it is why the master key
provider interface is shaped to let a remote KMS do the wrapping instead.

This is a portfolio project. It is built to the standard its subject matter demands and it has
been attacked, measured and documented honestly — including the parts that are not finished.
It has not been through an independent security review, and software that holds other people's
secrets should have one before it holds yours.

---

## Licence

The fonts in `src/Keystead.Web/wwwroot/fonts` are Mona Sans and Mona Sans Mono, used under the
SIL Open Font Licence; the licence travels with them in that directory.
