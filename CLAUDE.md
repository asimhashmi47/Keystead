# CLAUDE.md — Keystead conventions and standing rules

This file is the persistent contract for anyone (human or agent) working in this repository.
It outranks habit. If a change would violate a rule here, stop and fix the design instead.

---

## Non-negotiable security rules

1. **No placeholder crypto. Ever.** No `TODO`, no stub, no "fill this in later" in anything that
   touches a key, a hash, a token or a secret value. If it cannot be finished properly now, it
   does not get merged.
2. **Only `System.Security.Cryptography` primitives.** No custom algorithms, no hand-rolled KDF,
   no hand-rolled MAC, no "clever" XOR. Argon2id comes from a vetted library.
3. **AES-256-GCM only** for secret material: 256-bit key, 12-byte random nonce per operation,
   16-byte tag. Never reuse a nonce. Never derive a nonce from a counter or a timestamp.
4. **Every ciphertext is bound to its row with AAD.** The AAD always includes the full context
   path (workspace, vault, secret, version). A ciphertext must not decrypt in another row.
5. **Secret plaintext never leaves the intended path.** Never logged, never in an exception
   message, **never in a URL or query string**, never in a list payload, never in a DTO that
   reaches a view model. Zero the buffer with `CryptographicOperations.ZeroMemory` when done.

   On `GET`: a secret value must never be returned by a request a *browser* can be made to
   issue, because that puts it in history, in a shared cache, and in a referrer. The human UI
   therefore reveals only by `POST` with an antiforgery token. The machine API is a different
   case and `GET /api/v1/vaults/{id}/secrets/{name}` does return a value: it requires a bearer
   token no browser will attach, sends `Cache-Control: no-store`, and is the shape every SDK
   expects. The value is in the body, never the URL. Anything relaxing this needs the same
   three properties, stated at the call site.
6. **Constant-time comparison** for every hash, tag, token and code check
   (`CryptographicOperations.FixedTimeEquals`). Never `==` on secret-derived bytes.
7. **Deny by default.** The authorization fallback policy requires an authenticated principal.
   Every endpoint and page handler states its policy explicitly. A new endpoint with no policy
   is a bug, not a default.
8. **Every query is scoped by workspace**, and then authorization is checked separately.
   Scoping alone is not authorization; authorization alone is not scoping. Do both.
9. **No `Html.Raw`, no inline `<script>`, no inline event handlers, no `eval`, no CDN.**
   All JS, CSS and fonts are self-hosted and loaded as external files with a CSP nonce.
10. **No raw SQL string concatenation.** EF Core parameterized access only.
11. **No secrets in `appsettings*.json`.** Configuration is validated on startup and fails fast.
12. **Audit before you return.** Every read, write, login, permission change and failure writes an
    audit entry, and the entry is part of the hash chain.

---

## Code conventions

- **C# latest**, `nullable` enabled, `ImplicitUsings` disabled (explicit `using` lines — it makes
  the dependency direction visible).
- `TreatWarningsAsErrors` is on. A warning is a build failure. Do not suppress without a
  `#pragma` plus a comment explaining *why* it is safe.
- **File-scoped namespaces.** One public type per file, file named after the type.
- `sealed` by default on classes. `internal` unless a type genuinely needs to cross an assembly
  boundary.
- **Immutability preferred:** `record` for DTOs and value objects, `required` + `init` for
  entities, private setters elsewhere. No public mutable collections — expose
  `IReadOnlyList<T>`.
- **No `async void`.** Pass `CancellationToken` through every async call that can take one.
  Suffix async methods with `Async`.
- **Result over exceptions for expected failures** (not found, forbidden, validation). Exceptions
  are for genuinely exceptional conditions. Never put a secret in either.
- **Primary constructors** for dependency injection where they read cleanly.
- **Separate input models from entities.** Never model-bind straight onto an entity: that is how
  mass-assignment privilege escalation happens. Role and permission are never form-bound.

## Architecture rules

- Dependency direction: `Domain` <- `Application` <- `Infrastructure` <- `Web`.
  `Domain` references no project. If you need a reference that points outward, you need an
  interface in `Application` instead.
- `Web` is a composition root plus presentation. Business rules do not live in a page model.
- `Client` and `Cli` never reference server projects. They are HTTP consumers, so server crypto
  can never leak into a consumer application.
- Abstractions (`IMasterKeyProvider`, `ISecretCipher`, `IAuditChain`, `IClock`) are declared in
  `Application` and implemented in `Infrastructure`.
- `IClock` everywhere instead of `DateTimeOffset.UtcNow`, so expiry and rotation are testable.

## Testing rules

- Crypto changes require tests for: round trip, tampered ciphertext, tampered nonce, tampered
  tag, wrong AAD, wrong key, and rotation. A crypto change without a tamper test is incomplete.
- Security claims are tests, not comments. Every header, cookie flag and CSP directive promised
  in the README has an assertion in `Keystead.SecurityTests`.
- IDOR tests must actively *attempt* the cross-tenant access and assert the failure.
- Coverage target: above 85% on `Domain`, `Application` and `Infrastructure` crypto.
- Tests state behaviour: `Decrypt_WithTamperedTag_Throws`, not `Test1`.

## Git and milestone rules

- Build clean (zero warnings) and all tests green **before** every commit.
- One milestone per logical series of commits; a milestone is not done until its exit criteria in
  `PLAN.md` are met.
- Commit messages describe behaviour in plain language, present tense.

## UI rules

- Light theme, plain CSS with custom properties, no heavy framework.
- A persistent left sidebar on **every** authenticated page. Never a page without the shell.
- Semantic colour tokens only (`--color-danger`), never a raw hex in a component.
- Self-hosted variable font. Tabular numbers for metrics.
- Respect `prefers-reduced-motion`. Transitions 150-200ms.
- WCAG 2.2 AA contrast, visible focus rings, ARIA labels, full keyboard reachability.
- Secret values are masked by default, revealed only after step-up re-auth, fetched by `POST`
  with an antiforgery token and `Cache-Control: no-store`, auto-hidden after 30 seconds.
- Destructive actions use a typed-confirmation modal.
