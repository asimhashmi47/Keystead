# Deploying Keystead

Keystead holds credentials that unlock other systems. A deployment mistake here is worth more
to an attacker than most. This document is ordered by what breaks worst if you get it wrong.

---

## 1. The master key, before anything else

Every secret is encrypted under a key Keystead does not store. Read this section first.

### Generate it

```bash
mkdir -p ./secrets
openssl rand -base64 32 > ./secrets/keystead-master-key
chmod 600 ./secrets/keystead-master-key
```

### Back it up

**If you lose this file, the stored data is gone.** Not "recoverable with effort" — gone. There
is no escrow, no recovery service, and no master password. That is the point of the design: a
vendor who can recover your secrets is a vendor who can read them.

Put a copy somewhere that survives the loss of the server and is not the server: a password
manager, a sealed envelope in a safe, a different cloud account. Two copies in two places.

### Never do these

| Do not | Why |
|---|---|
| Put it in `appsettings.json` | It gets committed. There is deliberately no configuration option that accepts a key inline. |
| Put it in a `docker-compose.yml` `environment:` block | `docker inspect` prints the environment of a running container, and the compose file gets committed. |
| Bake it into an image layer | Image layers are distributed and cached. |
| Store it only in the same place as the database backup | One compromise then yields both the ciphertext and the key. |

### Supply it

Three providers, chosen with `Keystead:MasterKey:Source`:

| Source | Reads from | Use when |
|---|---|---|
| `Environment` | `KEYSTEAD_MASTER_KEY` (base64) | An orchestrator injects secrets as environment values |
| `File` | `Keystead:MasterKey:FilePath` (base64) | **Preferred.** A file can have an owner and a mode; an environment block is readable by anything that can see the process |
| `ProtectedFile` | DPAPI on Windows, mode 0600 elsewhere | Local development only |

The application **refuses to start** without a valid 256-bit key. That is deliberate: starting
without one would give you a process that looks healthy, accepts writes, and cannot decrypt
anything it stored.

Keystead refuses to read a key file that is readable beyond its owner. If you see
`is readable beyond its owner (mode ...)`, run `chmod 600`.

### The optional password pepper

`KEYSTEAD_PASSWORD_PEPPER`, base64, held wherever the master key is held. It is mixed into
password hashing, so a stolen database without the pepper cannot be attacked offline even for a
weak password.

**Decide this at setup time.** Adding a pepper later invalidates every existing password hash
and locks everyone out. There is a test asserting exactly that, so the behaviour will not
change quietly.

---

## 2. TLS, and the proxy that terminates it

Keystead sends HSTS and redirects plain HTTP. Its cookies use the `__Host-` prefix, which
browsers only accept over HTTPS. **The application will not work usefully without TLS**, and
the antiforgery system refuses to issue its cookie over an insecure request, so a misconfigured
deployment fails loudly rather than silently downgrading.

`deploy/Caddyfile` is the suggested configuration because Caddy obtains and renews certificates
itself. `deploy/nginx.conf` is there for an existing estate. Both set TLS 1.2 as the floor.

### The one setting people get wrong

Behind a proxy, the client address arrives in a header that **any client can set**. Keystead
trusts it only from the proxies you name:

```yaml
Keystead__ReverseProxy__KnownNetworks__0: "172.16.0.0/12"   # the Docker bridge
# or
Keystead__ReverseProxy__KnownProxies__0: "10.0.0.5"
```

Name **every** address the proxy may connect from. Naming one replaces the built-in loopback
trust rather than adding to it, so a proxy on the same host that connects over IPv6 needs `::1`
listed as well as `127.0.0.1` — otherwise the header is not trusted, and the only symptom is
that every client appears to be the proxy.

If you widen this carelessly — `0.0.0.0/0`, say — you disable the per-identity IP allowlist and
the per-address rate limits **while leaving their appearance intact**. The security centre would
still show an allowlist, and it would no longer mean anything.

So Keystead refuses to start on a range that wide. If every connection genuinely terminates at
a proxy that overwrites `X-Forwarded-For`, say so explicitly:

```yaml
Keystead__ReverseProxy__TrustAnyProxyAddress: "true"
```

Naming the proxy's own network is the better answer, and it is the one that keeps both controls.

The defaults trust loopback only, which is why this must be set when you put Keystead behind
anything.

Do not add or rewrite security headers at the proxy. Keystead sends a strict nonce CSP; a proxy
that injects its own would break the nonce and block the application's own scripts.

### Rate limits

The defaults suit a small team reaching the application directly. Every ceiling is
configurable, and the two that matter once there is a proxy in the path are the last two:

```yaml
Keystead__RateLimits__SignInAttemptsPerFiveMinutes: "10"
Keystead__RateLimits__MfaAttemptsPerFiveMinutes: "10"
Keystead__RateLimits__TokenIssuancesPerMinute: "30"
Keystead__RateLimits__SecretReadBurst: "120"
Keystead__RateLimits__SecretReadsPerMinute: "60"
Keystead__RateLimits__GlobalRequestsPerMinute: "600"
Keystead__RateLimits__RequestsPerMinutePerAddress: "6000"
```

Everything except the last is counted per caller: a signed-in person, or a service identity
identified by the bearer token it presents. `RequestsPerMinutePerAddress` is counted per source
address, and it is the ceiling nothing can talk its way around, so raise it with the number of
callers behind the proxy rather than with the traffic they send.

A value outside its documented range is a startup failure, not a silently clamped number.

---

## 3. Running it

### Docker Compose

```bash
openssl rand -base64 32 > ./secrets/keystead-master-key
chmod 600 ./secrets/keystead-master-key
# edit deploy/Caddyfile and replace keystead.example.com
docker compose up -d
```

What the compose file does and why:

- **`read_only: true`** with a `tmpfs` for `/tmp`. Nothing in the image needs to write to its
  own filesystem; the database is on a volume.
- **`cap_drop: ALL`**. Kestrel listens on 8080, so `NET_BIND_SERVICE` is never needed.
- **`no-new-privileges`**. There is no setuid binary in a chiselled image, but this survives a
  base image change.
- **The database on a named volume.** A container filesystem is ephemeral, and a secrets
  database that disappears on redeploy is an outage with no recovery.
- **A memory limit.** Turns a leak into a restart rather than the host swapping.

The image has no shell, so `docker exec` will not get you a prompt. That is the trade for
having nothing an attacker can pivot with. The health probe is the application itself
(`Keystead.Web --healthcheck`), for the same reason.

### Migrations

Applied automatically in Development only. In Production, run them as a deliberate step:

```bash
dotnet ef database update --project src/Keystead.Infrastructure
```

Automatic migration on startup means several instances racing to alter the same schema during
a rolling deploy, and it takes the decision to change a database holding irreplaceable key
material out of your hands.

### Configuration reference

| Setting | Default | Notes |
|---|---|---|
| `Keystead:Database:Path` | `data/keystead.db` | Keep it outside the web root |
| `Keystead:Database:BusyTimeoutMs` | `5000` | SQLite allows one writer; this waits rather than failing |
| `Keystead:Database:SqlCipherKey` | unset | See section 5 |
| `Keystead:MasterKey:Source` | `Environment` | See section 1 |
| `Keystead:PasswordHashing:MemoryKib` | `65536` | Raising it is safe; digests carry their own parameters |
| `Keystead:PasswordPolicy:MinimumLength` | `12` | The specified floor |
| `Keystead:Sessions:IdleTimeout` | `30m` | |
| `Keystead:Sessions:AbsoluteLifetime` | `12h` | Bounds a cookie stolen from an always-open browser |
| `Keystead:Sessions:StepUpWindow` | `5m` | How long a re-authentication stays fresh |
| `Keystead:Tokens:Lifetime` | `10m` | The window a leaked machine token is useful for |
| `Keystead:Tokens:RetiredKeyGrace` | `15m` | Must be at least `Lifetime`; validated on startup |

Options are validated on startup and the application fails fast on a bad value.

---

## 4. Backups

Back up **both**, and understand that they are different things:

1. **The database.** `keystead.db` plus its `-wal` and `-shm` files, or better,
   `sqlite3 keystead.db ".backup backup.db"` which is consistent without stopping the service.
2. **The master key.** Separately, somewhere else. See section 1.

A database backup without the key is unreadable. A key without the database is useless. Storing
them together means one compromise yields both.

Test the restore. A backup nobody has restored is a hypothesis.

---

## 5. Optional whole-database encryption

`Keystead:Database:SqlCipherKey` enables SQLCipher, which encrypts the whole file including
secret *names*, tags and the audit log. Those are plaintext columns otherwise, so a database
thief learns the shape of what you store even though they learn none of the values.

**It requires a SQLCipher-enabled native provider.** The stock `Microsoft.Data.Sqlite` native
library ignores the setting, which would give you a false sense of protection. It is off by
default for that reason. This is defence in depth over envelope encryption, never a substitute
for it.

---

## 6. After setup

1. Visit the installation. The first-run wizard creates your workspace and owner account, then
   closes itself permanently.
2. Record the master key fingerprint it shows. It is not the key; it lets you confirm later
   that you are holding the right one.
3. Enrol an authenticator. Owner and Admin cannot use the workspace without one.
4. **Save the recovery codes.** They are shown once.
5. Create a vault, then a service identity scoped to it. Give each application its own identity
   with the narrowest scope that works, so a leaked secret is a bounded incident.

## 7. Operating it

- **Rotate client secrets** from the identities page. The previous secret keeps working for an
  overlap window, so deployments move across without downtime.
- **Check the audit chain badge** on the audit page. It says `Chain verified` when every entry
  matches its hash and the sequence is unbroken. If it ever says otherwise, the entries before
  the break are still trustworthy and everything after should be treated as unreliable.
- **Review sessions** in the security centre. "Sign out everywhere" takes effect on the next
  request, not when cookies expire.
- **Watch for `TokenDenied` and `SignInFailed` bursts** in the audit log. Both are recorded as
  deliberately as successes.
- **Purge protection** on a vault means it can never be permanently destroyed, even after its
  recovery window elapses. Turn it on for anything you would not survive losing.
