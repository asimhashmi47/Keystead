# Security policy

## Reporting a vulnerability

Report privately, not in a public issue. Use GitHub's **Report a vulnerability** button on the
Security tab, which opens a private advisory.

Please include what you did, what happened, and what you expected. A proof of concept helps
enormously. If you are unsure whether something counts, report it: a false alarm costs an hour
and a missed report can cost someone their production credentials.

Do not test against anyone else's installation. Keystead is self-hosted, so run your own.

### What to expect

This is not a funded project with an on-call rota, so the honest answer is that response time
depends on who is available. No bounty is offered.

A report that turns out to be real gets: an acknowledgement, a fix, an advisory describing the
problem and which versions are affected, and credit in that advisory unless you ask otherwise.

---

## What is in scope

Anything that breaks one of the promises in [THREATMODEL.md](THREATMODEL.md). The ones worth
naming explicitly, because they are the product's core claims:

- Reading a secret value without the authorization to read it
- Reading anything across a workspace boundary
- Recovering secret plaintext from the database file without the master key
- Making a ciphertext decrypt in a row it was not sealed for
- Altering or removing an audit entry without verification failing
- Forging or extending a machine token, or using one past revocation
- Escalating from Reader or Contributor to anything administrative
- Escalating from Admin to Owner
- Causing a secret value to appear in a log, a URL, a list payload, or any cached response
- Bypassing step-up re-authentication on a reveal

## What is already documented as a limitation

These are known and written down in [THREATMODEL.md](THREATMODEL.md). A report that one of
them is true is appreciated but will be closed as already-known:

- A compromised host, or a memory dump taken during a reveal, yields plaintext
- Secret **names**, environments, tags and the audit log are not encrypted at rest
- Truncating the audit chain from the end is detectable but not preventable
- An Owner can grant themselves access to any vault in their workspace
- A reverse proxy configured to trust too wide a network defeats the IP allowlist
- Master-key and vault-KEK rotation have no scheduler yet

## Out of scope

- Reports with no security impact: missing headers on a static asset, a self-signed
  certificate warning in development, version disclosure that is not actually present
- Findings from an automated scanner with no demonstrated impact
- Denial of service by sending a very large volume of traffic
- Social engineering, physical access, or anything requiring a compromised administrator account
- Anything in a deployment that ignores [DEPLOYMENT.md](DEPLOYMENT.md), such as running without
  TLS or committing the master key

---

## How this project tries to stay secure

Not a promise that it is, which nobody can make. These are the things that would have to go
wrong for a vulnerability to ship unnoticed.

**Security claims are tests.** Every header, cookie flag and CSP directive promised in the
README has an assertion in `Keystead.SecurityTests`. Cross-tenant tests actively *attempt* the
crossing and assert the failure. The JWT suite performs `alg:none`, HS256 confusion, signature
forgery and replay, and asserts each is refused. A claim that is not tested is treated as a
claim that will quietly stop being true.

**Warnings fail the build.** `TreatWarningsAsErrors` is on, and every CA security rule
(CA2100, the CA3xxx family, the CA5xxx family) is raised to *error* in `.editorconfig`. A
suppression requires a `#pragma` and a comment explaining why it is safe; there are two in the
codebase and both say so.

**Rules no analyzer checks are greps.** `SourceRuleTests` enforces the absolutes from
`CLAUDE.md`: zero `Html.Raw`, zero inline script, zero inline event handlers, zero third-party
asset references, zero `eval`, zero `innerHTML` assignment, zero non-GCM cipher modes, zero
`==` on secret-derived bytes, and no `TODO` anywhere in security-critical code. These are
counts of zero rather than allowlists, so they cannot erode.

**Dependencies are pinned and audited.** Every version lives in `Directory.Packages.props`.
NuGet audit fails the build on a high-severity advisory. Dependabot opens weekly pull requests
and CodeQL runs at `security-and-quality` on every push and weekly on a schedule. A CycloneDX
SBOM is produced per build, so the next advisory against a transitive package is answerable
from a file.

**The container is minimal.** Chiselled base, no shell, non-root, read-only root filesystem,
every Linux capability dropped. CI asserts the configured user is not root.

### Cryptography

Only `System.Security.Cryptography` primitives. No custom algorithms, no hand-rolled KDF or MAC.

| Purpose | Choice | Why |
|---|---|---|
| Secret and key material | AES-256-GCM, 12-byte random nonce, 16-byte tag | Authenticated encryption; a tampered ciphertext fails rather than decrypting to rubbish |
| Nonces | 96 random bits per operation, never a counter | A counter resets on restart, restore or replication, and nonce reuse is catastrophic for GCM |
| Context binding | AAD covering workspace, vault, secret, version, purpose, key generation | Stops ciphertext being moved between rows |
| Human passwords | Argon2id, 64 MiB / t=3 / p=1, per-user salt, optional pepper | Above the OWASP floor; p=1 so concurrent sign-ins do not multiply memory |
| Machine tokens | ES256, algorithm pinned, rotatable `kid` | Asymmetric, so a verifier cannot mint tokens |
| Client secrets and recovery codes | 256 and 100 random bits, SHA-256 | High-entropy inputs; a slow hash would buy nothing and enable CPU exhaustion |
| Audit chain | SHA-256 over a length-prefixed canonical encoding | Length prefixes make the encoding injective, so two entries cannot collide |
| All comparisons | `CryptographicOperations.FixedTimeEquals` | Variable-time comparison leaks where a value first differs |

### Supported versions

Pre-release. There are no tagged releases yet, so only `main` is supported. Once releases
exist, this section will say which ones receive fixes.
