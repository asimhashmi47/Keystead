# Keystead threat model

What this product is defending, from whom, and where the defence stops. Written to be argued
with: every mitigation names the file that implements it and the test that holds it, and the
limitations section is not a formality.

---

## 1. Assets, in order of what their loss costs

| Asset | Why it matters | Where it lives |
|---|---|---|
| **Secret plaintext** | The thing customers trust us with. Its loss is the whole product failing. | Memory only, briefly, during a reveal |
| **Master key** | Decrypts every vault key, therefore every secret. Losing it destroys the data; leaking it destroys the confidentiality. | Outside the database: environment variable, mounted file, or DPAPI-protected file |
| **Vault KEKs** | Decrypt every secret in one vault | `vault_keks`, sealed under the master key |
| **Data keys (DEKs)** | Decrypt one secret version | `secret_versions.WrappedDek`, sealed under a KEK |
| **Token signing key** | Mints valid machine tokens, so forges any machine identity | `signing_keys`, private half sealed under the master key |
| **Password hashes** | Offline attack on human accounts | `users.PasswordHash`, Argon2id |
| **TOTP seeds** | Mints valid second factors | `users.MfaSecretCiphertext`, sealed under the master key |
| **Client secret hashes** | Machine authentication | `service_identities`, SHA-256 only |
| **Audit integrity** | Whether anyone can answer "who read this, and when" | `audit_entries`, hash chained |
| **Secret metadata** | Names, environments and tags map what is worth attacking | Plaintext columns, by necessity |

Note the last row. Secret *names* are not encrypted, and cannot usefully be: the product must
look them up to serve them. Someone who steals the database learns what kinds of credentials
exist and where, without learning any of them. This is accepted and is the reason optional
SQLCipher whole-database encryption exists.

---

## 2. Adversaries

| Adversary | Capability assumed | Primary concern |
|---|---|---|
| **Internet attacker** | Can reach the HTTPS endpoint | Credential stuffing, XSS, CSRF, enumeration |
| **Database thief** | Has a copy of the `.db` file, no keys | Reading secrets from the file alone |
| **Database writer** | Can modify rows, no keys | Moving ciphertext to reach what they may not, editing the audit log |
| **Low-privilege member** | A valid Reader account | Reaching vaults and tenants they were not granted |
| **Compromised application** | Holds a live service identity secret | Reaching beyond that identity's scope |
| **Malicious administrator** | Admin role in one workspace | Escalating to Owner, reaching another tenant, covering their tracks |
| **Host attacker** | Code execution or a memory dump on the server | Everything. See limitations. |

---

## 3. STRIDE

### Spoofing

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| Guessing a human password | Argon2id at 64 MiB / t=3, per-user salt, optional pepper held with the master key | `Argon2idPasswordHasher` | `Argon2idPasswordHasherTests` |
| Credential stuffing | Progressive per-account lockout plus per-address rate limiting | `User.RegisterFailedSignIn`, `Program.ConfigureRateLimiting` | `LockoutAndSessionTests`, `FlowTests.TheSignInEndpointIsRateLimited` |
| Discovering which accounts exist | One generic error; an unknown address runs the same Argon2id verification against a decoy digest | `SignInService` | `FlowTests.AWrongPasswordAndAnUnknownAccountAreIndistinguishable` |
| Password alone being enough | TOTP mandatory for Owner and Admin, checked at sign-in so a role promotion cannot leave a privileged account unprotected | `SignInService.RequiresMfaAsync` | `FlowTests.AnOwnerIsForcedIntoMfaEnrolmentRatherThanLetIn` |
| Replaying a captured TOTP code | Highest consumed time step recorded per user; a correct code is single-use | `TotpService.Verify`, `User.LastUsedTotpWindow` | `TotpServiceTests`, `FlowTests.AnAlreadyUsedCodeIsRefusedAsAReplay` |
| Stealing a session cookie | `__Host-` prefix, HttpOnly, Secure, SameSite=Strict, idle plus absolute timeout, server-side revocation on every request | `Program`, `SessionCookieValidator` | `ResponseHeaderTests`, `FlowTests.SigningOutRevokesTheSessionServerSide` |
| Forging a machine token | ES256 with the algorithm pinned to one value, so `alg:none` and HS256 confusion both fail; strict issuer, audience, expiry; 30-second skew | `TokenIssuer.ValidateAsync` | `TokenIssuerTests` (seven attack cases) |
| Reusing a leaked client secret | Short token lifetime, per-identity IP allowlist, revocation effective on the next call | `TokenIssuer`, `IpAllowlist` | `TokenIssuerTests`, `FlowTests.ARevokedIdentityCannotUseATokenItAlreadyHolds` |

### Tampering

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| Altering a secret's ciphertext | AES-256-GCM; any change fails the tag | `AesGcmCipher` | `AesGcmCipherTests` |
| **Moving ciphertext to another row** | AAD binds every ciphertext to workspace, vault, secret, version, purpose and key generation | `CryptoContext` | `SecretProtectorTests` (five relocation cases) |
| Swapping a wrapped key for a sealed value | Purpose is part of the AAD, so the two cannot stand in for one another | `CryptoPurpose` | `SecretProtectorTests.AValuePresentedAsItsOwnWrappedKey_FailsToOpen` |
| Rolling a row back to older ciphertext | The key generation is in the AAD, so a re-wrapped row cannot be reverted | `CryptoContext.ForDataKey` | `CryptoContextTests` |
| Editing the audit log | Each entry commits to the previous one over a length-prefixed canonical encoding | `AuditEntry.ComputeHash` | `AuditChainTests`, `AuditChainWriterTests` |
| Deleting an audit entry | Unique monotonic `Seq`; a gap is detected independently of the hashes | `AuditChain.VerifyAsync` | `AuditChainWriterTests.DeletingAnEntry_IsDetectedAsASequenceGap` |
| Cross-site request forgery | Global antiforgery auto-validation, SameSite=Strict | `Program`, `AutoValidateAntiforgeryTokenAttribute` | `FlowTests.AStateChangingPostWithoutATokenIsRefused` |
| Script injection | Strict nonce CSP from `default-src 'none'`, no `Html.Raw`, no inline script, no CDN, `textContent` in all scripts | `SecurityHeadersMiddleware` | `ResponseHeaderTests`, `SourceRuleTests` |
| SQL injection | EF Core parameterised access only; CA2100 and CA3001 are build errors | Analyzer configuration | `SourceRuleTests.NoSqlIsBuiltByConcatenation` |
| Mass-assignment escalation | Role and permission never model-bound; separate input models | `MembersModel` | `MembershipServiceTests` |
| Spreadsheet formula injection via the audit export | Leading `=`, `+`, `-`, `@` prefixed with an apostrophe | `AuditModel.Csv` | Covered by the export assertions in `scripts/smoke-flow.py` |

### Repudiation

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| Denying a secret was read | Every read audited before the value is returned | `SecretService.RevealAsync` | `SecretServiceTests.EveryRevealIsAudited_AndTheChainStaysIntact` |
| Denying a refusal happened | Denials recorded as deliberately as successes | All services | `SecretServiceTests.ADeniedReadIsAudited` |
| An audit write being skipped under load | Append failure is fatal to the operation, never swallowed | `AuditChain.AppendAsync` | `AuditChainWriterTests` |
| Attacker-controlled input breaking an audit write | Oversized fields truncated rather than rejected, so a 2 KB user agent cannot prevent a failed sign-in being recorded | `AuditChain.Truncate` | `AuditChainWriterTests.AnOverlongUserAgent_IsTruncatedRatherThanFailingTheWrite` |

### Information disclosure

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| Reading secrets from a stolen database | Envelope encryption; master key is not in the database | `SecretProtector` | `SecretProtectorTests` |
| A secret reaching a list payload | `SecretSummary` has no value field at all | `SecretContracts` | `SecretServiceTests.TheListPayload_CarriesNoValueAtAll` (reflection) |
| A secret reaching a log | Never passed to a logger; redaction enricher as a backstop | `SecretRedactionEnricher` | `LogRedactionTests` (captures the real sink) |
| A secret in browser history or a shared cache | Human reveal is `POST` only with antiforgery; `no-store` on every response | `SecretDetailModel.OnPostRevealAsync` | `ResponseHeaderTests`, smoke assertions |
| A secret left on screen or on the clipboard | Auto-hide after 30 seconds, clipboard overwritten | `reveal.js` | Smoke assertions |
| Cross-tenant reads | Every query scoped by workspace *and* authorized separately | `AccessPolicy` | `AccessPolicyTests` (six crossing attempts) |
| Stack traces and internals in errors | Safe error page with a correlation id only; RFC 7807 problems on the API | `ErrorModel`, `MachineApi.Problem` | `ResponseHeaderTests.AnApiFailureIsAProblemDocument` |
| Version banners aiding reconnaissance | `Server` and `X-Powered-By` removed | `SecurityHeadersMiddleware` | `ResponseHeaderTests.TheServerDoesNotAnnounceItself` |
| Secrets committed to the repository | `.gitignore` patterns, no secrets in `appsettings` | Configuration design | `SourceRuleTests.NoSecretIsCommittedInConfiguration` |

### Denial of service

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| Password-hash CPU exhaustion | Argon2id parallelism fixed at 1, so memory does not multiply across concurrent sign-ins; login rate limited | `Argon2idOptions` | Documented in the options |
| Large request bodies | Kestrel body, header and line limits; proxy limit as well | `Program.ConfigureKestrel` | — |
| Token endpoint grinding | Per-client rate limit; SHA-256 rather than Argon2id for high-entropy secrets | `Program`, `ClientCredential.Hash` | — |
| Regular expression backtracking | One-second match timeouts on every user-facing pattern | `SecretRedactionEnricher` | — |
| Account lockout used as a weapon | Lockout is progressive and time-bounded, never permanent | `User.RegisterFailedSignIn` | `LockoutAndSessionTests.TheLockoutExpires_OnItsOwn` |

### Elevation of privilege

| Threat | Mitigation | Implementation | Test |
|---|---|---|---|
| An endpoint with no policy | Authorization fallback requires an authenticated principal, so forgetting fails closed | `Program.ConfigureServices` | `ResponseHeaderTests.EveryAuthenticatedPageRefusesAnAnonymousCaller` |
| A Reader reaching a vault | Membership is not access; an explicit grant is required | `AccessPolicy` | `AccessPolicyTests.AReaderWithNoGrant_IsRefusedEvenInTheirOwnWorkspace` |
| A misconfigured grant promoting someone | Role ceiling caps whatever a grant says | `RoleCapabilities.Ceiling` | `AccessPolicyTests.AReaderHandedAWriteGrantByMistake_StillCannotWrite` |
| An Admin promoting themselves to Owner | Only an Owner may grant or remove the Owner role | `MembershipService.ChangeRoleAsync` | `MembershipServiceTests.AnAdminCannotPromoteThemselves` |
| A machine credential taking over a tenant | Service identities hold vault scopes only, never workspace capabilities | `AccessPolicy.AuthorizeWorkspaceAsync` | `AccessPolicyTests.AServiceIdentity_CannotPerformWorkspaceAdministration` |
| A long session authorising anything later | Step-up re-authentication required for reveal, purge, role change and identity creation | `AccessPolicy.RequireFreshStepUpAsync` | `SecretServiceTests.ARevealWithAStaleStepUp_IsRefusedWithAStepUpChallenge` |
| The setup wizard creating a second Owner | Initialisation refused once any user exists | `InstallationService` | `FlowTests.SetupClosesItselfOnceAnAccountExists` |
| Spoofing the client address to pass an allowlist | Forwarded headers trusted only from configured proxies | `Program`, `ForwardedHeadersOptions` | Documented in `DEPLOYMENT.md` |
| Open redirect after sign-in | `Url.IsLocalUrl` on every return parameter | `SignInModel`, `StepUpModel` | — |

---

## 4. Limitations

Stated plainly, because a threat model that claims completeness is not one.

**A compromised host reads everything.** Code execution on the server, or a memory dump taken
while a reveal is in flight, yields secret plaintext. `KeyMaterial` zeroes keys on disposal and
plaintext buffers are zeroed after use, which bounds *how long* a value is exposed. It does not
remove the exposure: the CLR may copy an array during a compacting collection, and nothing in
managed code prevents a dump. The master key provider interface is shaped so a remote KMS can
do the wrapping instead, which would move the key out of this process entirely. That is not
implemented.

**Secret metadata is not confidential.** Names, environments, tags and the audit log are
plaintext columns. A database thief learns the shape of what you store. SQLCipher behind a
config flag mitigates this and is documented but off by default, because the stock SQLite
provider ignores the setting and silently giving a false sense of protection would be worse
than not offering it.

**Audit truncation is detectable, not preventable.** Removing entries from the *end* of the
chain leaves a valid prefix. The `Seq` column makes the gap visible once anything is appended
afterwards, but an attacker who truncates and then stops has removed the record of their own
last actions. Preventing this needs an external witness — shipping hashes off-box — which is
not implemented.

**A privileged insider can still read secrets.** An Owner can grant themselves any vault. The
audit chain makes this visible, and step-up makes it deliberate; neither makes it impossible.
That is a property of the product being useful, not a defect.

**The IP allowlist is only as good as the proxy configuration.** It reads the resolved client
address. An operator who adds a wide network to `KnownNetworks` disables the control while
leaving its appearance intact. `DEPLOYMENT.md` says so in the place where the mistake would be
made.

**No bulk read means a slow SDK.** Loading configuration is one request per secret, which is
deliberate: a bulk endpoint would produce one audit entry covering a read of the whole vault
rather than a record of which secrets an application actually uses. For a vault with hundreds
of secrets this is noticeably slow.

**Master-key and vault-KEK rotation have no scheduler.** Both are modelled, stored with
version ids, and readable across generations, so rotation is possible without downtime. The
background job that performs the re-wrap is not written. Token signing key rotation *is*
implemented and tested.

**No clock authority.** Expiry, lockout and token lifetime trust the server clock. A clock
moved backwards extends token validity. Not mitigated beyond using UTC throughout.
