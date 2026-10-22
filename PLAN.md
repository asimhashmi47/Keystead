# Keystead — Implementation Plan

A self-hostable secrets manager (.NET 10, ASP.NET Core Razor Pages, EF Core, SQLite).
Concept-comparable to Azure Key Vault, scoped to an MVP a team can actually run.

---

## 1. Solution layout

Clean Architecture, dependencies point inward. Central Package Management, `nullable` enabled,
`TreatWarningsAsErrors`, latest analyzers including security analyzers.

```
Keystead.slnx
Directory.Build.props         # shared compiler/analyzer settings
Directory.Packages.props      # Central Package Management (all versions pinned here)
.editorconfig                 # analyzer severities, style enforced in CI
src/
  Keystead.Domain/            # entities, value objects, domain errors. No dependencies.
  Keystead.Application/       # use cases, abstractions (ports), FluentValidation validators
  Keystead.Infrastructure/    # EF Core + SQLite, crypto, key providers, audit chain
  Keystead.Web/               # Razor Pages UI + minimal API under /api/v1
  Keystead.Client/            # SDK + builder.Configuration.AddKeystead(...)
  Keystead.Cli/               # dotnet tool: login, vault, secret, run -- <cmd>
tests/
  Keystead.Tests/             # unit (crypto, hashing, chain, domain rules)
  Keystead.IntegrationTests/  # WebApplicationFactory: auth, RBAC, IDOR, scopes
  Keystead.SecurityTests/     # headers, CSP nonces, log redaction, source greps
samples/
  Keystead.Sample.Web/        # reads ConnectionStrings:Default via AddKeystead()
```

**Dependency rule.** `Domain` references nothing. `Application` references `Domain` only.
`Infrastructure` references `Application`. `Web` references `Application` + `Infrastructure`
(composition root only). `Client` and `Cli` reference neither — they talk HTTP, so the SDK
never drags server crypto into a consumer app.

---

## 2. Data model

Hierarchy: **Workspace** (tenant) > **Vault** > **Secret** > **SecretVersion**.

| Entity | Key fields | Notes |
|---|---|---|
| `Workspace` | Id, Name, Slug | Tenant boundary. Every query is scoped by it. |
| `Vault` | Id, WorkspaceId, Name, Slug, ColorToken, PurgeProtection, SoftDeletedUtc, RecoveryWindowDays | Owns a KEK. |
| `VaultKek` | Id, VaultId, Version, WrappedKek, MasterKeyVersion, IsActive | KEK wrapped by master key. |
| `Secret` | Id, VaultId, Name, ContentType, Environment, Enabled, ExpiresUtc, RotationReminderDays, SoftDeletedUtc | Name unique per (vault, environment). |
| `SecretTag` | SecretId, Key, Value | Filterable labels. |
| `SecretVersion` | Id, SecretId, Version, Ciphertext, Nonce, AuthTag, WrappedDek, KekVersion, Enabled, CreatedUtc, CreatedBy | One DEK per version. Never updated, only superseded. |
| `User` | Id, Email, PasswordHash, PasswordAlgo+Params, MfaSecretCiphertext, MfaEnabled, FailedCount, LockoutEndUtc | Argon2id. |
| `UserRecoveryCode` | UserId, CodeHash, UsedUtc | 10 single-use, hashed. |
| `UserSession` | Id, UserId, CreatedUtc, LastSeenUtc, Ip, UserAgent, RevokedUtc | Powers session list and "sign out everywhere". |
| `WorkspaceMembership` | UserId, WorkspaceId, Role | Owner / Admin / Contributor / Reader. |
| `VaultAssignment` | SubjectId, SubjectType, VaultId, Permission | Vault-level grant for users *and* identities. |
| `ServiceIdentity` | Id, WorkspaceId, Name, ClientId, ClientSecretHash, ExpiresUtc, IpAllowlist | Machine principal. |
| `AuditEntry` | Id, Seq, WorkspaceId, Actor, Action, Resource, Outcome, Ip, DataJson, **PrevHash, Hash** | Tamper-evident chain. |
| `MasterKeyVersion` | Version, CreatedUtc, RetiredUtc | Lets master rotation re-wrap KEKs. |

Soft delete everywhere that matters (`Vault`, `Secret`): a recovery window plus optional
purge protection, so a destructive click is survivable.

---

## 3. Cryptography design

Three-tier **envelope encryption**. Only `System.Security.Cryptography` primitives — no custom
algorithms, no placeholder crypto.

```
Master Key (256-bit, from IMasterKeyProvider, never persisted by the app)
  wraps -> Vault KEK (256-bit, per vault, versioned)
    wraps -> DEK (256-bit, unique per SecretVersion)
      encrypts -> secret plaintext
```

- **Cipher:** AES-256-GCM everywhere. 12-byte random nonce per operation, 16-byte tag.
  A fresh nonce per encryption, never reused, never derived from a counter.
- **AAD binds ciphertext to its row.** The value AAD is
  `workspaceId | vaultId | secretId | versionId` (plus a scheme tag). Moving a ciphertext blob
  to another row makes decryption *fail* rather than silently return someone else's secret.
  This is the defence against row-swap attacks by anyone with DB write access.
- **Master key providers** behind `IMasterKeyProvider`:
  (a) env var / file-mounted base64 key with validated length,
  (b) DPAPI (Windows) or 0600 protected file (Linux) for local dev,
  (c) interface shaped so Azure Key Vault / AWS KMS drop in later.
  First run shows a **recovery kit exactly once**. In Production the app **refuses to start**
  without a valid master key.
- **Rotation, no downtime, no plaintext on disk:** rotating the master key re-wraps KEKs;
  rotating a vault KEK re-wraps that vault's DEKs. Key version ids are stored so old rows stay
  readable mid-rotation.
- **Passwords:** Argon2id, documented parameters, per-user 128-bit salt, optional server-side
  pepper from the key provider. Fixed-time comparison via `CryptographicOperations`.
- **Client secrets / API tokens:** 256-bit random, `ksd_live_<base32>_<crc>` shape, stored only
  as SHA-256, shown once, rotatable with an overlap period.
- **Plaintext hygiene:** `byte[]` / `Span<byte>`, `CryptographicOperations.ZeroMemory` after use.
  Secret values never logged, never serialized into a DTO that reaches a list endpoint, never in
  an exception message, a URL or a query string. A log-redaction enricher plus a test that
  *proves* a known secret value never reaches the log sink.
- Optional SQLCipher whole-DB encryption behind a documented config flag.

---

## 4. Threat model summary (full STRIDE table in THREATMODEL.md)

Assets: secret plaintext, master/KEK/DEK material, password hashes, MFA seeds, audit integrity.

| Threat | Primary mitigation |
|---|---|
| Stolen DB file | Secrets are envelope-encrypted; master key lives outside the DB, so the file alone is useless. |
| DB write access, row swap | AAD binds every ciphertext to workspace/vault/secret/version. |
| Compromised web host memory | Short-lived plaintext, zeroed buffers, no plaintext caching. |
| Credential stuffing / brute force | Argon2id, lockout with progressive delay, rate limits, breach-list check, generic errors (no enumeration). |
| Stolen session cookie | `__Host-` prefix, HttpOnly, Secure, SameSite=Strict, idle plus absolute timeout, session revocation, step-up before any reveal. |
| Stolen client secret | Short-lived ES256 JWT, per-vault scopes, IP allowlist, expiry, rate limits, anomaly flags. |
| Malicious insider editing audit | Hash chain (each entry commits to the previous), verification page plus CLI verify. |
| XSS leading to secret exfiltration | Strict nonce CSP, no `Html.Raw`, no inline JS, no CDN, self-hosted assets. |
| CSRF | Global antiforgery auto-validation, SameSite=Strict, Origin/Referer checks. |
| IDOR across tenants | Every query scoped by workspace plus explicit authorization check, with tests that *attempt* the crossing. |
| Elevation via mass assignment | Separate input models; role/permission never bound from a form. |

---

## 5. Milestones

Each milestone ends with: `dotnet build` **zero warnings**, all tests green, then a commit.

| # | Scope | Exit criteria |
|---|---|---|
| **M1** | Scaffold, CPM, analyzers, config, Serilog, SQLite plus EF migrations, base layout and design system | Solution builds warning-free; app starts; migration applies |
| **M2** | Crypto core, master key providers, setup wizard | Round-trip, tamper, wrong-key and rotation tests pass |
| **M3** | Identity, Argon2id, TOTP MFA, recovery codes, sessions, RBAC, step-up | Auth, lockout and RBAC matrix tests pass |
| **M4** | Vaults, secrets, versions, soft delete/recover/purge, audit hash chain | Rollback and chain verification tests pass |
| **M5** | Service identities, `/api/v1/token`, machine API, scopes, rate limiting | Scope, IP allowlist and 429 tests pass |
| **M6** | Full UI: all pages, command palette, empty states, a11y pass | WCAG 2.2 AA contrast, keyboard nav, no layout shift |
| **M7** | Client SDK, CLI, samples, Docker, reverse proxy config | `AddKeystead()` sample runs; `keystead run --` injects env |
| **M8** | Security test suite, STRIDE doc, README/SECURITY/DEPLOYMENT, requirement traceability | Every spec line maps to a file or test |

---

## 6. Decisions taken up front

- **Razor Pages, not Blazor.** A strict nonce CSP with no inline script is far easier to hold,
  and this UI is forms-and-tables shaped.
- **Argon2id via a vetted library** (Konscious), not a hand-rolled KDF.
- **ES256 (asymmetric) for machine JWTs**, not HS256 — the verifier never needs signing material,
  and the signing key is rotatable with a `kid` header.
- **Progressive enhancement**, small external vanilla JS modules. No framework, no jQuery,
  no CDN — self-hosting is a CSP requirement, not a preference.
- **SQLite with WAL, `foreign_keys=ON` and a busy timeout**, DB path outside the web root, 0600 on Unix.
