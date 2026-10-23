# Keystead

A self-hostable secrets manager for developers and small teams: a central place to keep API
keys, connection strings, certificates and tokens, which applications fetch at runtime by name.

Built on .NET 10, ASP.NET Core Razor Pages, EF Core and SQLite. Concept-comparable to Azure
Key Vault, scoped to something a team can actually run on one box.

> **Status: in development.** Milestones M1 to M5 are complete and committed. Keystead is now
> usable for its stated purpose: a team can set it up, sign in with a second factor, store
> secrets, and an application can fetch them at runtime over the machine API with a scoped,
> short-lived token. The .NET SDK, the CLI and Docker packaging (M7) are not built yet, so
> applications currently call the API directly rather than through
> `builder.Configuration.AddKeystead(...)`. See [Current state](#current-state) for an honest
> breakdown, and [PLAN.md](PLAN.md) for the full plan.

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
entries cannot serialise to identical bytes. An insider with write access can still rewrite
rows; they cannot do it without verification failing.

**Deny by default.** The authorization fallback policy requires an authenticated principal, so
an endpoint that forgets to declare a policy fails closed rather than open.

---

## Current state

### Built and verified

| Area | What exists |
|---|---|
| Solution | 9 projects in Clean Architecture order; Central Package Management; `nullable`; warnings as errors; CA security rules at *error* |
| Cryptography | AES-256-GCM AEAD primitive; `CryptoContext` AAD binding; `KeyMaterial` with zeroing; three master key providers (environment, mounted file, DPAPI / 0600 file) |
| Passwords | Argon2id at 64 MiB / t=3 / p=1, per-user salt, optional pepper, PHC-encoded digests, rehash-on-upgrade |
| Audit | Tamper-evident hash chain with canonical encoding and verification |
| Persistence | Full 14-table schema, EF migration applied and checked, 36 indexes, SQLite pragmas (WAL, `foreign_keys`, busy timeout) per connection |
| Web hardening | Strict nonce CSP from `default-src 'none'`; full header set; `no-store`; no `Server` banner; antiforgery global; rate-limit policies; Kestrel limits |
| UI foundation | Design system in plain CSS with semantic tokens; app shell with persistent sidebar; progressive-enhancement JS module, no inline script |
| Identity | Argon2id sign-in with decoy-hash enumeration resistance; progressive lockout; TOTP with single-use replay guard; 10 single-use recovery codes; server-validated sessions with revocation |
| RBAC | Role/capability matrix as pure domain logic; vault grants with a role ceiling; workspace scoping and authorization checked separately on every call; step-up re-authentication |
| Setup | First-run wizard that closes permanently once an account exists; recovery kit with the master key fingerprint shown once |
| Vaults | Create, list, soft delete, recover, purge; per-vault key created with the vault; recovery window and purge protection enforced |
| Secrets | Append-only versions, enable/disable, soft delete and recover, expiry and rotation reminders, tags, environment scoping |
| Reveal | Masked by default, never in the page markup, fetched by `POST` with an antiforgery token, step-up required, `no-store`, auto-hides after 30 seconds |
| Rollback | Re-seals the old value as a new version rather than reviving the old row, so history stays append-only and the rollback is itself auditable |
| Audit viewer | Filterable log with a chain-verification badge and a CSV export that is guarded against spreadsheet formula injection |
| Service identities | `ksd_live_…` secrets with a checksum, stored as SHA-256, shown once; rotation with an overlap window; per-identity IP allowlist; revocation that bites on the next call |
| Machine API | OAuth2 client credentials to a short-lived ES256 token with a rotatable signing key; scoped per vault; RFC 7807 problem documents; ETag revalidation; `no-store` throughout |

**376 unit tests, all passing.** The failure cases carry the weight: tamper on ciphertext, nonce
and tag; wrong key; ciphertext moved to another workspace, vault, secret or version; purpose
confusion; nonce uniqueness across 200 seals; malformed and weaker-parameter password digests;
pepper mismatch; audit chain edit, rehash, delete and reorder detection; the full role matrix
checked exhaustively; TOTP replay and seed relocation; cross-tenant access attempted from six
directions and refused each time; and the full three-tier envelope with a value relocated to
another workspace, vault, secret and version, a data key spliced in from a different version,
and a value presented as its own wrapped key. The token suite performs the classic JWT attacks
and asserts each is refused: `alg: none`, HS256 confusion (signing with the public key as an
HMAC secret), a token signed by an attacker's key claiming the server's key id, a tampered
signature, a token with no key id, an expired token, and a token held by an identity that has
since been revoked.

**Verified against the running application**, not just in tests: the strict nonce CSP and full
header set; a fresh nonce per request; `/` and `/security` redirecting unauthenticated callers;
the first-run wizard closing itself after use; an Owner being forced into MFA enrolment rather
than let in; identical error pages for a wrong password and an unknown account; antiforgery
rejecting both a missing and a forged token with 400; the rate limiter returning 429; and the
audit chain linking correctly in the live database.

`scripts/smoke-flow.py` drives the running application through the whole flow and asserts 81
properties, including that the secret value appears in no list page, no detail page, no browser
`GET`, no API list response, no audit row, no CSV export; that a revoked identity cannot use a
token it already holds; and that the client secret never appears again after the one response
that issues it. Run it against a development instance with
`python scripts/smoke-flow.py https://localhost:5001`. M8 ports these assertions into
`Keystead.IntegrationTests` and `Keystead.SecurityTests`.

### Not yet built

Everything from milestone M6 onward in [PLAN.md](PLAN.md):
- **M6** — the remaining pages, command palette, accessibility pass
- **M7** — client SDK (`AddKeystead()`), CLI commands, Docker, reverse proxy config
- **M8** — integration and security test suites, STRIDE threat model, SECURITY.md, DEPLOYMENT.md

The CLI currently reports its version and prints the command surface it will gain in M7.

Known gaps within what is built: there is no OpenAPI document for the API yet (M7), no JWKS
endpoint (the public keys are stored and usable but not published), no workspace switcher,
vault grants for *users* are seeded directly rather than managed through a members page (M6 —
grants for service identities are managed on the identities page), the command palette is a
Ctrl+K shortcut that focuses search rather than a full palette (M6), and master-key and vault
KEK rotation are modelled and stored but have no background job to run them. Token signing key
rotation is implemented and tested. Revealing a secret in the browser requires JavaScript;
every other action works without it.

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

The application **refuses to start** without a valid 256-bit master key. That is deliberate:
starting without one would give you a process that looks healthy, accepts writes, and cannot
decrypt anything it stored.

Run the tests:

```bash
dotnet test
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
tests/Keystead.Tests         unit tests (crypto, hashing, audit chain)
tests/Keystead.IntegrationTests   WebApplicationFactory suites
tests/Keystead.SecurityTests      header, CSP and redaction assertions
```

[CLAUDE.md](CLAUDE.md) holds the conventions and the non-negotiable security rules that apply
to any change in this repository.

---

## A note on what cryptography here does and does not do

`KeyMaterial` zeroes key bytes on disposal, which bounds how long a key sits in memory. It does
not guarantee the key was never copied: the CLR may relocate an array during a compacting
collection, and nothing in managed code defends against a memory dump taken while a key is
live. That is a real limit, recorded here rather than hidden, and it is why the master key
provider interface is shaped to let a remote KMS do the wrapping instead.
