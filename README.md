# central-idp

A standalone, independently-authenticated identity service — a PoC
stand-in for an external centralized system that the primary application
integrates with. The full integration design (both access patterns this
service implements) is documented separately alongside the primary
application's own architecture docs.

Deliberately **not** part of `ems-platform` — no Eureka registration, no
Config Server dependency, its own repository and database — because it
represents a system the primary application integrates with, not a system it owns.

## What this service demonstrates

- BCrypt-12 password hashing for its own independent user store.
- JWT issuance with **key-ID-tagged, dual-key rotation support** — the
  signing key can be rotated without invalidating tokens issued moments
  before the rotation (see `JwtKeyProvider` / `rotate-secrets.sh`).
- Both integration patterns from `integration-design.md`:
  - **Pattern A** (portal-initiated): `GET/POST /api/v1/identity/authorize`
    — a real login page that redirects back to the calling app with a
    signed token.
  - **Pattern B** (app-initiated / credential relay): `POST
    /api/v1/identity/verify` — a client-authenticated API for a calling
    service to verify a user's credentials and receive identity claims
    back, without the raw credentials touching any UI here.

## Port

9090 (deliberately outside `ems-platform`'s 8080–8083 range)

## Project Files

| File | Purpose | Committed to Git? |
|---|---|---|
| `pom.xml` | Maven build definition and dependencies | Yes |
| `application.yml` | Spring Boot configuration (port, JWT settings, DB connection via env placeholders) | Yes |
| `db-schema.sql` | Creates the database, `identity_users` table, and one seed test user | Yes |
| `.env.example` | Template listing every environment variable this service needs, with placeholder values only — no real secrets | Yes |
| `.env` | The actual environment file with real generated secrets (JWT key, DB password, client secret) | **No — git-ignored, never committed** |
| `rotate-secrets.sh` | Rotates the JWT signing key (zero-downtime) or guides a database password rotation | Yes |
| `src/main/java/com/centralidp/entity/IdentityUser.java` | The user record model for this service's own independent user store | Yes |
| `src/main/java/com/centralidp/repository/IdentityUserRepository.java` | Data access for `IdentityUser` | Yes |
| `src/main/java/com/centralidp/security/JwtKeyProvider.java` | Loads and manages the current/previous signing keys for rotation | Yes |
| `src/main/java/com/centralidp/security/JwtService.java` | Issues and validates JWTs, using `JwtKeyProvider` | Yes |
| `src/main/java/com/centralidp/dto/VerifyRequest.java` / `VerifyResponse.java` | Request/response shape for Pattern B's `/verify` endpoint | Yes |
| `src/main/java/com/centralidp/controller/IdentityVerifyController.java` | Implements Pattern B (app-initiated / credential relay) | Yes |
| `src/main/java/com/centralidp/controller/IdentityAuthorizeController.java` | Implements Pattern A (portal-initiated login page + redirect) | Yes |
| `src/main/java/com/centralidp/config/SecurityConfig.java` | Disables Spring Security's default login form; provides the `BCryptPasswordEncoder` bean | Yes |

**Rule of thumb applied throughout this repo:** any file that only contains
*logic* (code, scripts, templates with placeholder values) is committed.
Any file that could contain a *real secret value* is git-ignored — see
`.gitignore` for the enforced list.

## Local setup

1. Create the database and seed user:
   ```bash
   mysql -u root -p < db-schema.sql
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

## Trying it out

**Pattern A (browser):**
```
http://localhost:9090/api/v1/identity/authorize?redirectUri=http://localhost:8080/api/v1/auth/sso/callback&state=xyz
```
Log in with `testvendor` / `Test@123` — you'll be redirected to
`redirectUri` with a `token` query parameter containing the signed
assertion.

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

## Relationship to `ems-auth`

`ems-auth` is the actual *consumer* of this service — it will need a new
adapter (see `integration-design.md` Section 5) implementing:
- A call to `POST /api/v1/identity/verify` for Pattern B.
- A redirect to `GET /api/v1/identity/authorize` and a new
  `/api/v1/auth/sso/callback` endpoint to receive the token for Pattern A.

That `ems-auth` side integration is tracked as the next build step, not
yet implemented as of this service's creation.
