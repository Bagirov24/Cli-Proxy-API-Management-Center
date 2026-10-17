# Backend16.15 — private mTLS exact-version PostgreSQL credential reader

**Status:** source-only, not mounted to `saas-control-api`. This is a
versioned secret-broker **client**, not a deployed secret service or an IAM
policy. It depends on Backend16.11, PR #60. No Railway services/variables,
permanent PostgreSQL, SQL0008 or production volumes are changed here.

## Purpose and protocol

`backend16PrivateMtlsVersionedSecretReader.ts` implements
`Backend16StagingVersionedSecretReader.readVersion(secretId,version,signal)`
from Backend16.11. The upstream versioned vault adapter independently
pins a static LOGIN → secret ID → immutable version manifest, then
independently validates the returned username, password, version and
short freshness lease **before** passing credentials to a single physical
PostgreSQL LOGIN. There is no generic secret URL or arbitrary version.

The broker is a **future** private, operator-provisioned Railway service
named `saas-secret-broker`, with intended internal hostname
`saas-secret-broker.railway.internal:443`. This name describes a release
contract, **not evidence the service exists**. It must be implemented,
reviewed and configured independently.

The one accepted mTLS operation is:

```http
GET /v1/staging/principals/b16-stg-pg-<opaque-id>/versions/<immutable-hex-version>
Accept: application/json
Cache-Control: no-store
Connection: close
```

The only successful response is HTTP 200, exactly
`Content-Type: application/json`, `Cache-Control: no-store`, with at
most 2048 UTF-8 bytes and one **canonical, compact JSON object** whose
property order is exactly `username,password,version,expiresAtMs`.
Any extra, duplicate, escaped-shadow, missing, stale, malformed or
noncanonical field is a refusal. The password is 32–256 printable ASCII
characters and the lease must have more than one and at most five minutes
remaining. Errors, 3xx redirects, absent versions, content encoding,
oversized bodies and protocol errors are not retried. A single client
request has a hard 4.2-second ceiling and caller abort cancels it.

No unauthenticated HTTP fallback, secret list/search, PUT/POST, arbitrary
host, `latest` alias, shared DB password, query-string credentials, JWT,
user header, token cache, logging, or public TCP proxy is available.

## Trust and transport

The client does not decide whether the operator-approved public
certificate digests are trustworthy. The **operator must independently
approve** both:

- SHA-256 of the genuine self-signed broker CA's DER certificate; and
- SHA-256 of the genuine short-lived client-authentication leaf's DER
  certificate, separately tied to an authorized workload identity.

The client requires single-PEM strong, time-valid root CA material and
a client certificate directly issued by that root with `clientAuth` EKU,
a matching PKCS#8 private key, its approved public fingerprint and
time-valid credentials. The client private key is **secret material**,
supplied only by a reviewed runtime secret bootstrap, never this
repository, GitHub Actions fixtures, a JWT or an end-user request.
JavaScript strings cannot be reliably zeroized.

Every outbound connection uses HTTPS, fixed private SNI, the approved
CA, `rejectUnauthorized:true`, TLS 1.2/1.3 and strict DNS SAN
validation requiring the **literal exact DNS SAN**, rejecting wildcard and
Common Name fallback. The Node standard identity
check also runs. A connection is not proof of broker IAM: **the actual
secret service must independently enforce mutual TLS workload identity,
read-only permissions to the exact permitted ID/version pairs, no
enumeration or writes, revocation, rotation and durable access audit**.

The staging constructor checks exact Railway project
`a9703851-6eb1-406c-bb15-7d3a89359fb7`, environment
`b0f5672b-8c91-44a3-a93e-0c5b8fde8d2b`,
`saas-control-api` service ID
`a0ff5420-95e8-4fab-88f6-623f75dd03c6`, private-only flag,
a separate explicit secret-broker approval flag, and refuses production,
GitHub Actions and insecure global TLS settings. This flag does not
substitute for a signed release decision.

A separate disposable-CI constructor accepts **loopback only** under
explicit GitHub Actions guards and keeps the same private SNI/SAN. It is
not an Internet, Railway or production fallback.

## Actual acceptance versus remaining evidence

The CI script
`scripts/saas-staging/verify-backend16-mtls-secret-broker-ci.ts`
creates a CA, client leaf, and server leaf with OpenSSL in a temporary
directory and runs a real TLS server that requires client certificates.
It checks a positive read through **both** this transport and the
Backend16.11 version-pinned vault adapter.
An additional child process runs the **actual Bun 1.3.14 mTLS client**
against the Node24 private HTTPS broker using the same temporary PKI,
without revealing certificate private keys in CI logs. This is a real
local mTLS read, not merely a Bun bundling/TypeScript check. It then exercises physical
revocation on the next request, wrong immutable version, expired
credentials, extra or duplicate fields, redirect, 404, oversized body,
hung/aborted response, invalid ID/version before network, wrong root
pin, wrong client leaf pin, mismatched client private key, and wrong
server SAN. All fixtures are synthetic and all generated private keys
are deleted after the CI run.

**This is still NOT a deployed external provider, IAM grant, live
credential, end-to-end PostgreSQL read, TLS trust approval or release
authorization.** Before mounting, operators must provision a broker,
review its implementation, verify mTLS peer identity and workload
authorization in permanent staging, rotate secrets with a reviewed
manifest update, archive broker audit evidence, and complete SQL0008
installed-mode, OIDC, off-host audit, recovery and two-tenant canary
gates. PR #62's signed evidence verifier cannot manufacture those
proofs. Keep production Core/Gateway, `custom-no-apikey-fun`, and
`/data` unchanged until separately approved production deployment.
