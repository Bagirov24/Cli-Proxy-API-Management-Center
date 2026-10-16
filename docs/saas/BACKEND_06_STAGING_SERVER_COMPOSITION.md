# Backend 06 — isolated staging HTTP composition (16 October 2026)

This is a **fetch-only composition**, not a Railway deployment, mounted API, production-ready gateway or approval of persistent PG migrations. It creates no listener or public port. Only `main` plus this PR's reviewed branch is in scope; CPA Core/Gateway sources, volumes and credentials are untouched.

## Wiring

`createSaasStagingHttpComposition(env, ports)` connects operator-pinned public RS256 JWKS access-token verification, SQL026/027 durable issuer/subject actor and current-membership resolution, token-bound sessions, signed RLS PostgreSQL reads, and signed project POST/PATCH writers. Every external port must be independently implemented and validated by operators: isolated identity pool with physical discard, least-privileged signed read/write pools, signer, revision reader, persistent mandatory audit recorder, durable off-host intent journal, and operational readiness. No insecure defaults or synthetic fallbacks are supplied.

A future host can expose `GET /internal/healthz` (liveness) and `GET /internal/readyz` (operator readiness). These routes **are not authentication-protected** and therefore MUST be restricted to private monitoring ingress. Their minimal JSON conveys no internal diagnostics. Request routing accepts GET/POST collection and PATCH item, on an exact configured HTTPS origin, with no redirects or CORS. Existing handlers independently enforce bearer, tenant and signed DB authorization. Each API request first requires readiness, with no implicit retry after UNKNOWN COMMIT.

## Startup requirements

All must be set: `SAAS_HTTP_EXPLICIT_ENABLE=true`, `SAAS_RUNTIME_PROFILE=isolated-staging`, `SAAS_NETWORK_POLICY=private-only`, `RAILWAY_ENVIRONMENT=staging`, a single exact HTTPS `SAAS_EXTERNAL_ORIGIN`, `SAAS_OIDC_ISSUER`, `SAAS_OIDC_AUDIENCE` and `SAAS_OIDC_PINNED_PUBLIC_JWKS_JSON` approved out of band. For synthetic GitHub CI, `SAAS_EPHEMERAL_COMPOSITION_CI=true` is additionally required. These strings are **not** proof of Railway private-network enforcement; operators must check ingress/egress independently. Do not supply OAuth or PG secrets in the git repository. The default is failure to initialize.

## Not accepted or claimed

No network listener, real IdP onboarding/login, server-held browser cookie or CSRF design, production DB migration, backup/restore, production physical-pool quarantine proof, WORM/reconciliation, distributed revocation, or Gateway/CPA integration is added. SQL001–027 remain ephemeral pilot scripts; SQL019 must not be auto-applied. A 503 after a committed mutation MUST NOT be retried or reissued automatically. The temporary SQL027 proof is **not** a safe Railway PG schema bootstrap. Next work: independently verified physical connection termination + persistent staging database and least-privileged migration/backup runbook, followed by security and operator approval.
