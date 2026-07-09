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
