# central-idp

A standalone, independently-authenticated identity service — a PoC
stand-in for an external centralized system that the primary application
integrates with. The full integration design (both access patterns, plus
the registration and identity-linkage model) is documented separately
alongside the primary application's own architecture docs
(`external-system-integration-design.md`).

Deliberately **not** part of `ems-platform` — no Eureka registration, no
Config Server dependency, its own repository and database — because it
represents a system the primary application integrates with, not a
system it owns.

## What this service demonstrates

- BCrypt-12 password hashing for its own independent user store.
- A durable, stable identity key (`externalId`, a UUID) issued once per
  identity and never reused — the actual link key any consumer should
  use, never `username` (see "Identity model" below).
- Self-service registration, independent of any consuming application.
- JWT issuance with **key-ID-tagged, dual-key rotation support** — the
  signing key can be rotated without invalidating tokens issued moments
  before the rotation (see `JwtKeyProvider` / `rotate-secrets.sh`).
- Both integration patterns from `external-system-integration-design.md`:
  - **Pattern A** (portal-initiated): `GET/POST /api/v1/identity/authorize`
    — a real login page that redirects back to the calling app with a
    signed token.
  - **Pattern B** (app-initiated / credential relay): `POST
    /api/v1/identity/verify` — a client-authenticated API for a calling
    service to verify a user's credentials and receive identity claims
    back, without the raw credentials touching any UI here.
- Two security fixes found and closed during PoC testing (reflected XSS,
  open redirect) — see `security-and-compliance.md` for details.

## Identity model

Every identity has three distinct identifiers, and they serve different
purposes — worth being precise about, since confusing them is an easy
mistake for a consumer to make:

| Field | Purpose |
|---|---|
| `id` (internal DB primary key) | Never exposed outside this service |
| `externalId` (UUID) | **The durable link key.** Consuming applications (e.g. `ems-auth`) should store and look up by this, never by username. This is the JWT `sub` claim. |
| `username` | Display/login identifier — could in principle be changed later without the underlying identity changing |

## Port

9090 (deliberately outside `ems-platform`'s 8080–8083 range)

## Project Files

| File | Purpose | Committed to Git? |
|---|---|---|
| `pom.xml` | Maven build definition and dependencies | Yes |
| `application.yml` | Spring Boot configuration (port, JWT settings, DB connection via env placeholders) | Yes |
| `db-schema-v2.sql` | Creates the database, `identity_users` table (with `external_id` and `email`), and one seed test user | Yes |
| `migration-add-external-id.sql` | For installations from before `external_id`/`email` existed — adds both columns to an existing table | Yes |
| `.env.example` | Template listing every environment variable this service needs, with placeholder values only — no real secrets | Yes |
| `.env` | The actual environment file with real generated secrets (JWT key, DB password, client secret) | **No — git-ignored, never committed** |
| `rotate-secrets.sh` | Rotates the JWT signing key (zero-downtime) or guides a database password rotation | Yes |
| `central-idp.postman_collection.json` | Full test suite — 28 requests across registration, both patterns, health, and JWT rotation, including regression tests for the two security fixes | Yes |
| `central-idp.postman_environment.json` | Matching Postman environment (baseUrl, test credentials, client secret placeholder) | Yes |
| `src/main/java/com/idp/entity/IdentityUser.java` | The user record model — includes `externalId` (durable link key) and `email` | Yes |
| `src/main/java/com/idp/repository/IdentityUserRepository.java` | Data access for `IdentityUser` | Yes |
| `src/main/java/com/idp/security/JwtKeyProvider.java` | Loads and manages the current/previous signing keys for rotation | Yes |
| `src/main/java/com/idp/security/JwtService.java` | Issues and validates JWTs (subject = `externalId`), using `JwtKeyProvider` | Yes |
| `src/main/java/com/idp/dto/VerifyRequest.java` / `VerifyResponse.java` | Request/response shape for Pattern B's `/verify` endpoint | Yes |
| `src/main/java/com/idp/dto/RegisterRequest.java` / `RegisterResponse.java` | Request/response shape for self-service `/register` | Yes |
| `src/main/java/com/idp/controller/IdentityVerifyController.java` | Implements Pattern B (app-initiated / credential relay) | Yes |
| `src/main/java/com/idp/controller/IdentityAuthorizeController.java` | Implements Pattern A (portal-initiated login page + redirect); includes redirect-allowlist and XSS-escaping fixes | Yes |
| `src/main/java/com/idp/controller/IdentityRegisterController.java` | Self-service registration — always assigns the default `CITIZEN` role, never client-settable | Yes |
| `src/main/java/com/idp/config/SecurityConfig.java` | Disables Spring Security's default login form; provides the `BCryptPasswordEncoder` bean | Yes |

**Rule of thumb applied throughout this repo:** any file that only contains
*logic* (code, scripts, templates with placeholder values) is committed.
Any file that could contain a *real secret value* is git-ignored — see
`.gitignore` for the enforced list.

## Local setup

1. Create the database and seed user (fresh install):
   ```bash
   mysql -u root -p < db-schema-v2.sql
   ```
   Or, if upgrading an existing installation that predates `external_id`/`email`:
   ```bash
   mysql -u root -p < migration-add-external-id.sql
   ```
   Seed user: `testvendor` / `Test@123`
2. Copy `.env.example` to `.env` and fill in real values:
   ```bash
   cp .env.example .env
   openssl rand -base64 48   # run twice, once each for JWT_CURRENT_KEY_SECRET and EMS_AUTH_CLIENT_SECRET
   ```
3. Run:
   ```bash
   mvn spring-boot:run
   ```
4. Import `central-idp.postman_collection.json` and `central-idp.postman_environment.json` into Postman, fill in `clientSecret` in the environment, and run the full suite.

## Trying it out

**Registration (API):**
```bash
curl -X POST http://localhost:9090/api/v1/identity/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser1","password":"Test@1234","fullName":"New User One","email":"newuser1@example.com","department":"MSME Services"}'
```
Returns a `201` with the new identity's `externalId` — this is the value
any consuming application should store, never the username.

**Pattern A (browser):**
```
http://localhost:9090/api/v1/identity/authorize?redirectUri=http://localhost:8080/api/v1/auth/sso/callback&state=xyz
```
Log in with `testvendor` / `Test@123` — you'll be redirected to
`redirectUri` with a `token` query parameter containing the signed
assertion. Note `redirectUri` must be in the configured allowlist
(`ALLOWED_REDIRECT_URIS` in `.env`) or the request is rejected before any
token is issued.

**Pattern B (API):**
```bash
curl -X POST http://localhost:9090/api/v1/identity/verify \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: ems-auth" \
  -H "X-Client-Secret: <value from .env>" \
  -d '{"username":"testvendor","password":"Test@123"}'
```

## Credential rotation

```bash
chmod +x rotate-secrets.sh   # first time only
./rotate-secrets.sh jwt      # zero-downtime JWT key rotation
./rotate-secrets.sh db       # guided database password rotation
```

Every rotation should also be recorded in `ems-docs/security-and-compliance.md`.

**Reminder:** `ems-auth` validates tokens using a copy of this service's
JWT signing key (shared-secret HMAC, a deliberate PoC simplification —
see `external-system-integration-design.md`). After rotating the JWT key
here, `ems-auth`'s `.env` (`CENTRAL_IDP_JWT_CURRENT_KEY_SECRET` and
`CENTRAL_IDP_JWT_PREVIOUS_KEY_SECRET`) must be updated to match, ideally
before the previous key ages out on this side.

## Relationship to `ems-auth`

**Implemented.** `ems-auth` is the consumer of this service, via
`CentralIdpAdapter` (in `com.enterprise.microservice.integration`):
- `POST /api/v1/identity/verify` — called from `ems-auth`'s `POST
  /api/v1/auth/sso/login` (Pattern B).
- `GET /api/v1/identity/authorize` → `ems-auth`'s `GET
  /api/v1/auth/sso/callback` receives the resulting token (Pattern A).
- `POST /api/v1/identity/register` — called from `ems-auth`'s `POST
  /api/v1/auth/register/sso`, the sole registration path into the
  platform (`ems-auth`'s own local-only registration has been retired —
  see `external-system-integration-design.md` Section 8).

On first touch via any of the three, `ems-auth` auto-provisions a local
profile row linked by `externalId`, with a role mapped from this
service's `role` claim via `ems-auth`'s own config.
