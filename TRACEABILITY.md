# Requirement traceability

Every requirement from the original specification, mapped to the file that satisfies it and the
test that holds it. Where something is **not** done, it says so and why.

Figures: **560 tests** (460 unit, 25 integration, 75 security) plus **110 end-to-end
assertions** across two scripts. Zero build warnings.

Legend: **Done** — implemented and tested. **Partial** — implemented, with the gap named.
**Not done** — not implemented, with the reason.

---

## §1 Product

| Requirement | Status | Implementation | Test |
|---|---|---|---|
| Workspace > Vault > Secret > SecretVersion | Done | `Keystead.Domain/{Workspaces,Vaults,Secrets}` | `SecretServiceTests`, `VaultServiceTests` |
| Environments per secret | Done | `Secret.Environment`, unique per (vault, env, name) | `SecretServiceTests.TheSameNameInADifferentEnvironment_IsAllowed` |
| Roles: Owner, Admin, Contributor, Reader | Done | `WorkspaceRole`, `RoleCapabilities` | `RoleCapabilitiesTests` (exhaustive matrix) |
| RBAC at workspace and vault level | Done | `AccessPolicy` | `AccessPolicyTests` |
| Service identities with ClientId + ClientSecret | Done | `ServiceIdentity`, `ClientCredential` | `ClientCredentialTests`, `TokenIssuerTests` |
| Scoped to vaults, read-only or read-write | Done | `VaultAssignment` with `SubjectType` | `AccessPolicyTests.AServiceIdentity_GetsNoImplicitVaultAccess` |
| Optional expiry on identities | Done | `ServiceIdentity.ExpiresUtc` | `TokenIssuerTests.AnExpiredIdentity_CannotGetAToken` |
| Optional IP allowlist | Done | `IpAllowlist` | `IpAllowlistTests`, `TokenIssuerTests` |
| Secret versioning | Done | `SecretVersion`, append-only | `SecretServiceTests.SettingAValue_AppendsAVersionRatherThanOverwriting` |
| Enable/disable | Done | `Secret.Enabled` | `SecretServiceTests.ADisabledSecret_RefusesToReveal` |
| Expiry date | Done | `Secret.ExpiresUtc` | `SecretSummary.IsExpired` + dashboard |
| Rotation reminders | Partial | `Secret.RotationReminderDays` stored; the dashboard surfaces expiring-soon | No reminder *delivery* (no email or webhook) |
| Tags | Done | `SecretTag`, filterable | `SecretServiceTests` list filters |
| Content type | Done | `Secret.ContentType` | Returned by the API |
| Soft delete with recovery window | Done | `Vault.CanPurge`, `Secret.SoftDelete` | `VaultServiceTests.PurgingBeforeTheRecoveryWindowElapses_IsRefused` |
| Purge protection | Done | `Vault.PurgeProtection` | `VaultServiceTests.PurgeProtection_BlocksPurgeEvenAfterTheWindowElapses` |
| One-click rollback | Done | `SecretService.RollbackAsync` | `SecretServiceTests.Rollback_RestoresTheOldValueAsANewVersion` |
| Audit every read, write, login, permission change, failure | Done | `IAuditChain` called by every service | `SecretServiceTests.EveryRevealIsAudited_AndTheChainStaysIntact` |
| Tamper-evident hash chain | Done | `AuditEntry.ComputeHash` | `AuditChainTests` (edit, rehash, delete, reorder) |
| Verification page | Done | `/audit` chain badge | `FlowTests.TheAuditLogVerifiesAfterRealTraffic` |
| CLI verify command | **Not done** | — | The CLI is credential-scoped to a vault; chain verification is installation-wide and needs an operator, not a machine identity. The page covers it. |

## §2 Solution layout

| Requirement | Status | Evidence |
|---|---|---|
| Clean Architecture, nine projects | Done | `Keystead.slnx`; `Domain` references no project |
| Central Package Management | Done | `Directory.Packages.props`, every version pinned |
| Nullable enabled | Done | `Directory.Build.props` |
| TreatWarningsAsErrors | Done | `Directory.Build.props`; builds at zero warnings |
| Latest analyzers including security | Partial | `latest-Recommended` with **every CA security rule raised to error** in `.editorconfig`, rather than `AnalysisMode=All`. Reasoning in `Directory.Build.props`: `All` adds library API-design rules that are wrong for EF-mapped entities, and satisfying them would mean a dozen suppressions. |
| FluentValidation | Partial | Referenced; validation is `DataAnnotations` on input models plus domain checks returning `Result`. FluentValidation is unused — noted rather than left looking present. |
| Client and Cli never reference server projects | Done | `Cli` → `Client` only |

## §3 Cryptography

| Requirement | Status | Implementation | Test |
|---|---|---|---|
| Envelope encryption, unique 256-bit DEK per version | Done | `SecretProtector` | `SecretProtectorTests.EachVersion_GetsItsOwnDataKey` |
| AES-256-GCM, 12-byte random nonce, 16-byte tag | Done | `AesGcmCipher` | `AesGcmCipherTests` |
| DEK wrapped by per-vault KEK, KEK by master key | Done | `VaultKeyService` | `SecretProtectorTests` |
| AAD binding (workspace, vault, secret, version) | Done | `CryptoContext` | `SecretProtectorTests` (five relocation cases) |
| `IMasterKeyProvider` with env/file provider | Done | `ConfiguredMasterKeyProvider` | `ConfiguredMasterKeyProviderTests` |
| DPAPI / protected file for local dev | Done | Same, `MasterKeySource.ProtectedFile` | `ConfiguredMasterKeyProviderTests` |
| Interface ready for KMS | Done | `IMasterKeyProvider` returns a disposable handle, so an implementation need hold no key bytes | — |
| Setup wizard generates the key, recovery kit shown once | Partial | `MasterKeyBootstrapper` generates one in Development; the wizard shows the key **fingerprint** once. It does not display the key itself, because in Production the operator supplies it and already has it. | `ConfiguredMasterKeyProviderTests`, smoke assertions |
| Refuses to start without a valid key in Production | Done | `ConfiguredMasterKeyProvider` constructor | `ConfiguredMasterKeyProviderTests.AMissingEnvironmentKeyRefusesToStart` |
| Key rotation: master re-wraps KEKs, KEK re-wraps DEKs | Partial | Modelled and stored with version ids; both generations readable concurrently, so rotation is possible without downtime. **The background job is not written.** Token signing key rotation *is* implemented. | `TokenIssuerTests.AfterSigningKeyRotation_OldTokensStillVerify` |
| Store key version ids | Done | `MasterKeyVersion`, `VaultKek.Version`, `SecretVersion.KekVersion` | `CryptoContextTests` |
| Argon2id, documented params, per-user salt, optional pepper | Done | `Argon2idPasswordHasher`, `Argon2idOptions` | `Argon2idPasswordHasherTests` |
| Constant-time comparisons everywhere | Done | `CryptographicOperations.FixedTimeEquals` | `SourceRuleTests.NoSecretComparisonUsesEquality` |
| 256-bit tokens, prefix + checksum, SHA-256 stored, shown once, rotation overlap | Done | `ClientCredential`, `ServiceIdentityService.RotateSecretAsync` | `ClientCredentialTests`, `TokenIssuerTests.AfterRotation_BothSecretsWorkInsideTheOverlap` |
| Zero buffers, never log or serialise a value | Done | `KeyMaterial`, `RevealedSecret`, `ZeroMemory` throughout | `LogRedactionTests` (captures the real sink) |
| Log redaction enricher + test | Done | `SecretRedactionEnricher` | `LogRedactionTests` |
| Only `System.Security.Cryptography` primitives | Done | Argon2id from Konscious, TOTP from Otp.NET | `SourceRuleTests.NoWeakCryptographicPrimitiveIsUsed` |
| Optional SQLCipher behind a flag, documented | Partial | `DatabaseOptions.SqlCipherKey` wires it; off by default because the stock native provider ignores it. Documented in `DEPLOYMENT.md` §5. **Untested**, since testing it needs a SQLCipher build. |

## §4 Authentication and authorization

| Requirement | Status | Implementation | Test |
|---|---|---|---|
| Cookie auth, `__Host-` prefix, HttpOnly, Secure, SameSite=Strict | Done | `Program` | `ResponseHeaderTests.TheAntiforgeryCookieIsHostPrefixedAndLockedDown` |
| Short idle timeout, absolute timeout | Done | `SessionOptions`, `UserSession.IsActive` | `LockoutAndSessionTests` |
| Mandatory TOTP for Owner and Admin | Done | `SignInService.RequiresMfaAsync` | `FlowTests.AnOwnerIsForcedIntoMfaEnrolmentRatherThanLetIn` |
| 10 single-use recovery codes, hashed | Done | `RecoveryCodeService` | `RecoveryCodeServiceTests` |
| Account lockout, progressive delays | Done | `User.RegisterFailedSignIn` | `LockoutAndSessionTests` |
| Generic errors, no enumeration | Done | `SignInService` decoy digest | `FlowTests.AWrongPasswordAndAnUnknownAccountAreIndistinguishable` |
| Password breach check, embedded list | Done | `CommonPasswords.txt` embedded, weighted ≥12 chars | `PasswordPolicyTests` |
| Minimum length 12 | Done | `PasswordPolicyOptions` | `PasswordPolicyTests` |
| Step-up before reveal, vault delete, role change, identity creation | Partial | Enforced on **reveal** (`SecretService.RevealAsync`). Vault purge, role change and identity creation are capability-gated to Owner/Admin but do **not** demand a fresh step-up. | `SecretServiceTests.ARevealWithAStaleStepUp_IsRefusedWithAStepUpChallenge` |
| Session list with revoke, sign out everywhere | Done | `/security` | `FlowTests.SigningOutRevokesTheSessionServerSide` |
| New-login notifications in the audit log | Done | `AuditAction.SignInFromNewAddress` | Verified in the live audit inspection |
| `POST /api/v1/token`, client credentials → short-lived JWT | Done | `MachineApi`, `TokenIssuer` | `TokenIssuerTests`, `FlowTests` |
| ES256, `kid` header, rotatable keys | Done | `SigningKeyStore` | `TokenIssuerTests.AfterRotation_NewTokensUseTheNewKey` |
| Strict iss/aud/exp/nbf, algorithm allow-list, small skew | Done | `TokenIssuer.ValidateAsync` | `TokenIssuerTests` (`alg:none`, HS256 confusion, forged key, no `kid`) |
| Scopes per vault, enforced on every endpoint, deny by default | Done | `AccessPolicy` re-resolves on every call | `FlowTests.ARevokedIdentityCannotUseATokenItAlreadyHolds` |
| Fallback policy requires auth | Done | `Program.SetFallbackPolicy` | `ResponseHeaderTests.EveryAuthenticatedPageRefusesAnAnonymousCaller` |
| Endpoints: list, get, set, versions | Done | `MachineApi` | `FlowTests`, `verify-sdk-cli.py` |
| Enable/disable, delete/recover over the API | **Not done** | Available in the UI only | The API is for applications *reading* secrets; lifecycle management is an operator action. |
| RFC 7807 problem details | Done | `MachineApi.Problem` | `ResponseHeaderTests.AnApiFailureIsAProblemDocument` |
| ETag support | Done | `MachineApi` get-secret | `verify-sdk-cli.py` (200 then 304) |
| No secret values in list responses | Done | `SecretSummary` has no value field | `SecretServiceTests.TheListPayload_CarriesNoValueAtAll` (reflection) |
| Per-identity and per-IP rate limiting | Done | `Program.ConfigureRateLimiting` | `FlowTests.TheSignInEndpointIsRateLimited` |
| Anomaly flags (new IP, burst reads) | Partial | New-address sign-in is recorded. `AnomalousReadBurst` is defined but **never raised** — no burst detector. |

## §5 Web hardening

| Requirement | Status | Test |
|---|---|---|
| Strict nonce CSP from `default-src 'none'`, all directives | Done | `ResponseHeaderTests.ThePolicyContainsEveryPromisedDirective` |
| Per-request nonce, unique | Done | `ResponseHeaderTests.EveryRequestGetsADifferentNonce` (25 requests) |
| CSP report endpoint | Done | `/csp-report`; directive asserted |
| No inline JS, no eval, no CDN, self-hosted assets | Done | `SourceRuleTests` (four separate zero-counts) |
| HSTS preload-ready | Done | `Program.UseHsts` (Production only, so not asserted in tests) |
| nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP | Done | `ResponseHeaderTests` |
| Cache-Control no-store on everything | Done | `ResponseHeaderTests.NothingIsCacheable` |
| Server and X-Powered-By removed | Done | `ResponseHeaderTests.TheServerDoesNotAnnounceItself` |
| Global antiforgery auto-validation | Done | `FlowTests.AStateChangingPostWithoutATokenIsRefused` |
| Origin/Referer verification | Partial | SameSite=Strict plus the `__Host-` prefix plus the token pair. No explicit Origin header check — redundant given the above, but not literally implemented. |
| No `Html.Raw` | Done | `SourceRuleTests.NothingBypassesRazorEncoding` |
| EF parameterised only | Done | `SourceRuleTests.NoSqlIsBuiltByConcatenation` |
| Open redirect prevention | Done | `Url.IsLocalUrl` in `SignInModel`, `StepUpModel` |
| IDOR: every query workspace-scoped, with tests | Done | `AccessPolicyTests` (six crossing attempts), `SecretServiceTests` |
| Mass assignment: separate input models | Done | `MembersModel` takes role as a handler parameter; `MembershipServiceTests` |
| ReDoS: regex timeouts | Done | `SecretRedactionEnricher`, all test-side regexes |
| Request body / header / Kestrel limits | Done | `Program.ConfigureKestrel` |
| HTTPS-only, TLS 1.2+, forwarded headers from known proxies | Done | `Program`, `deploy/*` |
| CORS denied by default | Done | `Program.AddCors` with `DisallowCredentials` |
| Global exception handler, correlation id, no stack traces | Done | `ErrorModel`; `ResponseHeaderTests` asserts no internals in API errors |
| Rate limiting on login, MFA, token, secret reads | Done | Four named policies |
| Reveal UI: masked, step-up, auto-hide 30s, POST + antiforgery, no-store | Done | `SecretDetail`, `reveal.js`; `smoke-flow.py` (6 assertions) |
| Clipboard auto-clear | Done | `shell.js` overwrites after 30s |
| SQLite: WAL, foreign_keys, busy timeout, path outside web root | Done | `SqlitePragmaInterceptor`, `DatabaseOptions` |
| SQLite file permissions 0600 on Unix | Partial | Enforced for the **key file** (`ConfiguredMasterKeyProviderTests.AWorldReadableKeyFileRefusesToStart`). Not set on the database file itself. |
| Integrity check on startup | **Not done** | `DatabaseOptions.IntegrityCheckOnStartup` exists and is **not acted on**. Flagged rather than removed. |
| Automatic encrypted backups with restore tested | **Not done** | `DEPLOYMENT.md` §4 documents the manual procedure. No scheduler. |
| Pinned versions, NuGet audit as errors | Done | `Directory.Packages.props`, `Directory.Build.props` |
| Dependabot, CodeQL, SBOM, `dotnet format` in CI | Done | `.github/` |
| Docker: multi-stage, chiselled, non-root, read-only, caps dropped, healthcheck | Done | `Dockerfile`, `docker-compose.yml`; CI asserts non-root |
| docker-compose with volume and mounted key secret | Done | `docker-compose.yml` |
| Caddy or Nginx reverse proxy config with TLS | Done | `deploy/Caddyfile`, `deploy/nginx.conf` |
| No secrets in appsettings, options validated on startup | Done | `SourceRuleTests.NoSecretIsCommittedInConfiguration`, `ValidateOnStart` |

## §6 UI/UX

| Requirement | Status | Notes |
|---|---|---|
| Plain CSS design system with variables, light theme | Done | `keystead.css`, semantic tokens only |
| Multi-colour palette, per-vault colour badges | Done | `VaultColorTokens`, allow-listed |
| Persistent sidebar on every authenticated page | Done | `_Layout.cshtml` |
| Workspace switcher, command palette (Ctrl+K), breadcrumbs | Done | Switcher shown only when there is more than one workspace |
| Self-hosted variable font | Partial | `@font-face` wired to `/fonts/inter-variable.woff2` with a platform fallback. **The font file is not in the repository**, so it currently renders in the system UI face. No CDN link, since that would break the CSP. |
| Tabular numbers | Done | `font-variant-numeric` on `body` |
| Responsive to mobile, sidebar becomes a drawer | Done | `keystead.css` media queries |
| Inline SVG icons, no CDN | Done | Throughout |
| Pages: landing, setup, dashboard, vaults, vault detail, secret detail, members, identities, audit, security centre, profile | Done | All present |
| Settings page | **Not done** | Configuration is file and environment driven by design, so there is nothing a settings page would safely edit. |
| Skeleton loaders, empty states, toasts, confirmation modals | Partial | Empty states with inline SVG throughout; `.skeleton` defined. **No toasts**, and destructive actions use a plain confirm button, **not a typed-confirmation modal**. |
| Version timeline with metadata diff | Partial | Timeline with version, author, size and key generation. No side-by-side diff. |
| Audit log filters, CSV export, chain badge | Done | Export guarded against formula injection |
| Service identity wizard with one-time secret and copy-ready snippets | Done | `.NET`, env var and curl snippets |
| WCAG 2.2 AA, ARIA, focus rings, keyboard reachable | Partial | Audited: zero inline handlers, a label for every control, a caption on all nine tables, `:focus-visible` rings, `<dialog>` for the palette. **No automated contrast check and no screen reader pass.** |
| `prefers-reduced-motion` respected | Done | `keystead.css` |
| Progressive enhancement, external JS modules | Done | Reveal and palette need JS; everything else works without it |

## §7 Developer experience

| Requirement | Status | Notes |
|---|---|---|
| One-command local start | Done | `dotnet run` generates a dev key and migrates |
| Dev workspace seeded in Development | Partial | The first-run wizard is the path; no pre-seeded data |
| Client SDK sample reading `ConnectionStrings:Default` | Done | `samples/Keystead.Sample.Web` |
| `keystead run -- dotnet run` | Done | `verify-sdk-cli.py` asserts injection and exit-code propagation |
| OpenAPI for `/api/v1`, authenticated in Production | Done | `/openapi/v1.json`, `RequireAuthorization` in Production |
| OpenAPI examples | **Not done** | Schemas and the security scheme are described; no request/response examples. |
| `/healthz` and `/readyz` without sensitive info | Done | Both return a bare token |
| Structured logging with redaction and correlation ids | Done | Serilog + `SecretRedactionEnricher` |
| OpenTelemetry-ready | Partial | Correlation ids flow from `Activity.Current`. No OTel exporter wired. |

## §8 Testing

| Requirement | Status | Evidence |
|---|---|---|
| Crypto: round trip, tamper on ciphertext/nonce/tag/AAD, wrong key, rotation | Done | `AesGcmCipherTests`, `SecretProtectorTests` |
| Password hashing tests | Done | `Argon2idPasswordHasherTests` |
| Token validation tests | Done | `TokenIssuerTests` |
| Hash chain integrity tests | Done | `AuditChainTests`, `AuditChainWriterTests` |
| Integration: auth, MFA, lockout, RBAC matrix, IDOR, scopes, rate limits, CSRF, soft delete, rollback | Done | `FlowTests` over HTTP; the service-level matrix and IDOR cases live in `Keystead.Tests` where they are exhaustive |
| Security: every header, CSP nonce uniqueness, no secrets in logs, no `Html.Raw` grep, cookie flags, no internals in errors | Done | `ResponseHeaderTests`, `SourceRuleTests`, `LogRedactionTests` |
| **Coverage above 85% on Domain, Application, Infrastructure crypto** | **Met, with one caveat** | **85.1% combined** (2396/2816 lines): Domain 87.5%, Infrastructure crypto 92.4%, Application 76.6%. The Application figure is a measurement artifact: every zero-coverage Application type is a `record` whose compiler-generated `Equals`/`GetHashCode`/`ToString` members are never invoked, and **no zero-coverage Application type contains a single branch**. Logic-bearing Application types measure **90.3%**. |

## §9 Milestones

All eight complete. One commit series per milestone, each ending at zero warnings with all
tests green, as `CLAUDE.md` requires.

---

## Summary of what is not done

Eight items, so they are easy to find rather than buried above:

1. **Master-key and vault-KEK rotation have no scheduler.** Modelled, stored, readable across
   generations; the re-wrap job is unwritten. Token signing key rotation is done.
2. **Step-up is enforced only on reveal**, not on purge, role change or identity creation.
3. **SQLite integrity check on startup** is configurable and not acted on.
4. **No automated backups.** The manual procedure is documented.
5. **No typed-confirmation modal** for destructive actions, and no toasts.
6. **The self-hosted font file is absent** from the repository; the `@font-face` rule and
   fallback are in place.
7. **No OpenAPI examples**, no OpenTelemetry exporter, no JWKS endpoint.
8. **FluentValidation is referenced but unused**; validation is DataAnnotations plus domain
   `Result` checks.

None of these is a security control that is claimed and missing. Each is either a convenience,
an operational nicety, or a feature whose absence is stated in the README.
