# Keystead

A self-hostable secrets manager for developers and small teams: a central place to keep API
keys, connection strings, certificates and tokens, which applications fetch at runtime by name.

Built on .NET 10, ASP.NET Core Razor Pages, EF Core and SQLite. Concept-comparable to Azure
Key Vault, scoped to something a team can actually run on one box.

> **Status: in development.** Milestones M1 and M2 are complete and committed. The
> cryptographic core is implemented and tested; the user-facing features that sit on top of it
> are not yet built. See [Current state](#current-state) below for an honest breakdown, and
> [PLAN.md](PLAN.md) for the full plan.

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

**73 unit tests, all passing.** The failure cases carry the weight: tamper on ciphertext, nonce
and tag; wrong key; ciphertext moved to another workspace, vault, secret or version; purpose
confusion; nonce uniqueness across 200 seals; malformed and weaker-parameter password digests;
pepper mismatch; and audit chain edit, rehash, delete and reorder detection.

### Not yet built

Everything from milestone M3 onward in [PLAN.md](PLAN.md):

- **M2 remainder** — first-run setup wizard and one-time recovery kit
- **M3** — sign-in, TOTP MFA, recovery codes, sessions, RBAC enforcement, step-up re-auth
- **M4** — vault and secret use cases, versioning, soft delete and recovery, audit writing
- **M5** — service identities, `/api/v1/token`, the machine API, scope enforcement
- **M6** — the remaining pages, command palette, accessibility pass
- **M7** — client SDK (`AddKeystead()`), CLI commands, Docker, reverse proxy config
- **M8** — integration and security test suites, STRIDE threat model, SECURITY.md, DEPLOYMENT.md

The CLI currently reports its version and prints the command surface it will gain in M7. The
dashboard renders the shell with placeholder counts, so the layout and design system are
exercised against a real page.

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
