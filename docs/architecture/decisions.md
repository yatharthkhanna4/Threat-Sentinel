# Architecture decisions

These decisions describe the current architecture and its boundaries; they do not imply that deferred product capabilities have been implemented.

## Phase 2D.2 account lifecycle and recovery

The [account lifecycle assessment](./account-lifecycle-assessment.md) records the trust model,
state transitions, owner consequences, and recovery decision for this phase.

- `User.status` has the existing `active`, `suspended`, and `deactivated` values. Authentication
  and protected operations reject non-active local users. No account suspension authority or
  reactivation authority exists.
- `POST /api/v1/account/deactivate` permits an authenticated principal to explicitly deactivate
  only its own active account. The request has a strict confirmation schema; it does not accept a
  user ID or status. A deactivated account cannot use protected APIs, including to reactivate.
- The operation preserves identity and membership history. Under the existing User → Organization
  → Membership lock order it rejects deactivation when any organization would have no other active
  OWNER backed by an active User. No owner role is transferred.
- Historical note (superseded): the initial design record for this decision originally stated that
  there was no durable audit-event store. That statement is superseded by the current database-
  backed security audit implementation in
  `threat_sentinel_api.modules.audit.service.AuditService`, its `SecurityAuditEvent` model, and
  the versioned organization audit-events API. Supported lifecycle transitions and lifecycle denial
  events are now persisted with actor attribution and structured bounded details. This does not
  make the audit log tamper-proof or implement retention enforcement.
- There is no provider administrative integration, platform control plane, or organization owner
  recovery authority. Suspension, reactivation, privileged recovery, and organization access
  restoration remain deferred. Application request logs are not a replacement for the durable audit
  event store.
- Deactivation does not revoke external identity-provider sessions or already issued JWTs. The
  local active-user check denies subsequent protected API requests after commit; in-flight work is
  not retroactively cancelled.

The status values predate this operation, so no migration is required. Do not mark Phase 2D
complete while suspension, recovery, durable auditability, and owner-loss recovery remain absent.

| Area | Decision |
| --- | --- |
| Repository | Monorepo with `apps/web`, `apps/api`, `packages/shared-contracts`, infrastructure, docs, scripts, and tests. |
| Frontend | Next.js App Router, strict TypeScript, Tailwind CSS, shadcn/ui-compatible component organization, and Lucide icons. |
| Backend | Python with FastAPI, Pydantic Settings, SQLAlchemy 2.x, and Alembic. |
| Database | PostgreSQL is the architectural database direction. PostgreSQL 17 is the local and CI target for concurrency integration tests; no production provider has been selected. |
| JavaScript packages | pnpm workspace. |
| Python packages | uv project and lockfile. |
| Testing | Vitest for frontend smoke tests, Pytest for API tests, and Playwright for browser-level testing. |
| Local infrastructure | Docker Compose for PostgreSQL only. |
| Deployment | Managed cloud direction; no production provider selected. Avoid provider lock-in where practical. |
| AI | Future multi-provider design with local and cloud inference adapters; no vendor dependency is introduced. |
| Service topology | A modular monolith until demonstrated scaling or operational requirements justify extraction. No Kubernetes or speculative microservices. |
| Identity key | Internal users have stable UUIDs; external accounts map by the exact verified `(issuer, subject)` pair. Email is mutable metadata, not an account key or linking mechanism. |
| Authentication boundary | Keep untrusted bearer credentials, verifier-produced access-token claims, resolved local application identity, and authorization decisions separate. The provider-neutral adapter returns only the minimal typed verified claims; local identity resolution produces a principal only for an active user. Issuer, audience, JWKS URL, and allowed algorithms are trusted out-of-band settings and must be configured together. JWT verification and reusable FastAPI authentication and tenant dependencies are implemented. The protected scan routes consume authentication; the scan service owns authorization. |
| Tenant authorization | Authorization uses local user identity, active local membership, locally assigned organization role, and resource scope. Current reader paths serialize against authorization-state writers with PostgreSQL row locks. Provider-supplied roles, permissions, or organization claims never grant local access. No role hierarchy, implicit permission inheritance, or authorization caching is introduced. |
| Transaction ownership | Request-scoped `get_session()` does not commit implicitly. Scan and principal-resolution application operations use one `unit_of_work()`. Organization service/repository methods remain transaction-neutral; their caller must own one UOW spanning active-user validation, locks, and writes. |
| Invitations | A partial unique index permits one pending invitation per organization and normalized email. Invitations bind to a verified external identity, store only a token hash, expire after seven days, and are single-use. There is no email-delivery integration; authorized creation returns the token once. |
| Owner retention | Membership role/status changes and explicit ownership transfer validate the projected state under the canonical PostgreSQL lock order. An organization retains an active owner; ownership transfer is atomic. |

## Consequences

- `/api/v1` is the HTTP API version boundary.
- `DATABASE_URL` is optional at startup; database-backed operations require explicit readiness, failure, and migration behavior.
- Authentication configuration is optional at startup. Readiness reports whether local authentication settings are configured; it does not check JWKS or provider availability. Protected scan routes fail closed when authentication configuration is absent.
- Future shared TypeScript contracts should describe API boundaries, not reimplement backend rules.
- External identity resolution uses the exact `(issuer, subject)` pair. A previously unknown verified identity may create a local user and external identity mapping, but this provisioning creates no organization or membership. Organization creation explicitly grants the creator the initial owner membership.
- Authentication verification, local identity resolution, and tenant authorization are separate
  reusable dependencies/contracts. Protected scan and account/organization lifecycle APIs mount
  authentication and perform server-side authorization in their own UOWs; they do not rely on a
  separate tenant dependency result as a grant.
- The first product resource is a Website/Domain Security Scan. Its model, scoped repository,
  lock-protected authorization-aware service, and protected persistence routes are implemented;
  scan execution and analysis are not.
- `VerifiedUserContext` remains the Phase 2A issuer/subject and email-metadata contract used by
  existing identity and tenancy services; it is not a bearer credential or proof of token
  verification. The reusable authentication dependency produces `AuthenticatedPrincipal` only
  after successful token verification and active local identity resolution.
- `VerifiedAccessTokenClaims` is an internal minimal verifier-output contract: exact issuer and
  subject, audience, timezone-aware issuance and expiration, optional not-before, key ID, email
  metadata, and token type. It contains no raw token or arbitrary provider claims; provider-supplied
  organization, role, permission, membership, and group claims are not included in verifier output.
  The type itself does not verify a token.
- Authentication verifier settings are optional at application startup, but issuer,
  audience, HTTPS JWKS URL, and explicit supported algorithms must be supplied together. Missing
  configuration causes a generic 503 when the authentication dependency is invoked. The settings
  validate trusted inputs; they do not enable authentication or make a token trustworthy.
- The verifier accepts only compact JWT access tokens with the RFC 9068 `at+jwt` type
  marker, using keys from the configured JWKS URL and the configured algorithm allowlist. It pins
  HTTPS requests to resolved public IP addresses, rejects redirects, bounds response size and
  timeouts, and limits key refreshes. A reusable authentication dependency invokes the verifier,
  and a reusable tenant dependency checks local active membership. The protected scan routes consume
  the authentication dependency, while service operations authorize organization scope within
  their own UOW. PyJWT (MIT) and its
  `cryptography` dependency (Apache-2.0/BSD-3-Clause) are free/open-source and add no provider or
  paid service.
- Repository/service writes must be grouped in exactly one application-boundary-owned `unit_of_work()`; request session cleanup does not imply a commit. Scan, account profile, organization, membership, and invitation routes own the transaction spanning authorization and their state changes.
- Persistence models are internal and must not be exposed directly as public API response contracts.
- Product security and privacy decisions must precede collection or processing of user-provided threat evidence.

### Initial Website-Domain Security Scan authorization (service and protected routes implemented)

Each scan belongs to exactly one logical access scope: a personal workspace or an organization
workspace. The creator/audit identity is distinct from the authorization scope. The server assigns
the owner of a personal scan from the authenticated principal; client-supplied owner IDs never
establish ownership. Authenticated users may create personal scans and may list/read only their own;
personal scans do not require organization membership.

Organization scan-record persistence operations require an active local user, active organization,
and active local membership. The following matrix applies only to the Phase 2 persistence routes;
role names do not imply any additional permissions on those routes:

| Action | OWNER | ADMIN | MEMBER | VIEWER |
| --- | --- | --- | --- | --- |
| Create organization scan | Allow | Allow | Allow | Deny |
| Read organization scan | Allow | Allow | Allow | Allow |
| List organization scans | Allow | Allow | Allow | Allow |

Resource lookups must constrain resource ID and authorized scope together in the data-access
query. A missing resource and an out-of-scope resource return the same generic `404`; a caller
with access to the scope but without permission for the action receives a generic `403`. Internal
audit logging may distinguish denial reasons without disclosing them to clients. The six service
operations enforce this policy inside one unit of work. Personal operations lock
and revalidate the local user and exact external identity mapping. Organization operations lock
and validate the user, organization, and membership in canonical order. A shared transaction
alone does not prevent authorization-state races. No role hierarchy, implicit permission
inheritance, or authorization caching is used. The six persistence routes are mounted only after
the route layer, service authorization, error mapping, and HTTP integration tests were implemented.
This does not claim production readiness or deployment-specific security approval.

Domain services classify denials without returning HTTP status codes. `ScanNotFound` and
`OrganizationScopeUnavailable` represent missing or inaccessible resources/scopes and map to a
generic `404` in the API layer. `OrganizationPermissionDenied` represents an active member's
disallowed action and maps to a generic `403`. `InvalidPrincipalError` (including inactive-user
and identity-mapping revalidation failures) maps to a generic `401` with the bearer challenge.
These responses use the standard generic HTTP error envelope and do not disclose resource,
organization, membership, or internal denial details. The specific exceptions preserve their
outcome distinction; the compatibility `OrganizationAccessDenied` base is not itself mapped.
Product scan routes use these handlers and are mounted under `/api/v1`; no scan execution,
findings, or analysis capabilities are exposed.

The product-owner-approved future Phase 3 target, execution, findings, evidence, and cancellation
permissions are specified separately in the
[Phase 3 architecture blueprint](./phase-3-architecture.md#authorization-matrix-and-api-boundary).
This is one of nine approved architecture decisions; the complete Phase 3A specification remains
formally approved and closed. Phase 3B is authorized and underway; Phase 3B.1 hostname
canonicalization is implemented and pending final acceptance. Phase 3B.2 adds organization target
and challenge persistence; Phase 3B.3 adds server-side DNS TXT ownership verification and atomic
challenge consumption for organization targets. No target API is exposed and no challenge rate
limits are implemented.
**IP Destination Policy v1 was approved by the project owner on 2026-11-24.**
The approved policy is implemented as authoritative IANA snapshots, a versioned normalized policy
artifact, a pure address evaluator, and tests. Phase 3B.4.1–3 additionally implement immutable
resolution models and secure dual-stack DNS A/AAAA resolution. Phase 3B.4.4 implements the
one-shot pinned HTTP/TLS transport, strict HTTP/1.1 response parsing, and bounded scan accounting.
Production-provider egress review remains required before production deployment.

These deliverables do not implement Phase 3C, a queue, worker, scanner, or public target route.
The canonical resolver algorithm and positive IPv4/IPv6 policy design are in the
[Phase 3 architecture proposal](./phase-3-architecture.md#dns-aaaa-resolution-proposal) and
[IP-policy section](./phase-3-architecture.md#explicit-ipv4ipv6-policy). The transport implementation
does not constitute production egress approval or add scan execution. These capabilities do not
alter Phase 2 scan-record permissions. Challenge issuance and verification rate limits remain
prerequisites before exposing target API routes.

### Authorization transaction and concurrency protocol (implemented; PostgreSQL integration tests)

The implementation uses PostgreSQL's default transaction isolation. PostgreSQL 17 is the local
and CI concurrency-test target; passing local integration tests is not evidence of production
deployment, provider equivalence, or production readiness.

All authorization-sensitive operations acquire row locks in this order:

1. User rows, sorted by UUID.
2. The organization row, when applicable.
3. Invitation rows, sorted by UUID, when applicable.
4. Membership rows, sorted by UUID.

Reader queries use SQLAlchemy `.with_for_update(read=True, of=Model)` and PostgreSQL `FOR SHARE`.
Writer queries use `.with_for_update(key_share=True, of=Model)` alone and PostgreSQL
`FOR NO KEY UPDATE`. Locks are held through the authorization decision and protected database
work, until commit or rollback. Lock primitives are separate single-table queries; authorization
does not rely on joined eager-loading to establish lock order. Locks for multiple rows of one type
are acquired one at a time in UUID order.

Current protected readers are:

- `ScanService.create_personal_scan`, `list_personal_scans`, and `get_personal_scan`: lock the
  authenticated local User `FOR SHARE`, revalidate the exact issuer/subject identity ID and user
  ID, then check active status and perform the existing owner/scope-constrained scan query in the
  same UOW.
- `ScanService.create_organization_scan`, `list_organization_scans`, and `get_organization_scan`,
  plus tenant membership authorization: lock User, Organization, then Membership `FOR SHARE`.
  The membership query includes inactive rows; status and locally stored role are checked after
  locks. Missing membership still locks the Organization, the serialization point when no
  Membership row exists. The existing permission matrix and generic 404/403 behavior are retained.
- Active-user principal resolution in `IdentityService.resolve_verified_user` and
  `resolve_authenticated_principal`: lock User `FOR SHARE`, refresh its row, then revalidate the
  exact external identity mapping before active status validation/principal issuance. No separate
  ExternalIdentity lock is used.
- Organization listing: lock User first; enumerate all of that user's memberships without an
  active-status filter; lock every relevant Organization in UUID order; then lock every relevant
  Membership in UUID order. Retain all locks through active-status filtering and list
  materialization. Membership writers acquire the user's `FOR NO KEY UPDATE` lock first, which
  prevents additions or changes from appearing as phantom memberships during listing.

Organization creation obtains the exact identity mapping, locks User `FOR SHARE`, then validates
active status after acquiring that lock. The lock remains held through insertion of the Organization
and initial active OWNER Membership in the route's single transaction. It does not upgrade the
User lock or mutate the User row; User `FOR SHARE` blocks a protocol-compliant User status writer
using `FOR NO KEY UPDATE`. The Organization insert precedes the Membership insert. The service and
repository do not open nested UOWs.

Identity provisioning for a previously unknown verified identity continues to insert User and
ExternalIdentity atomically in the principal-resolution UOW. There is no production operation
that reassigns, unlinks, or relinks an existing identity. Any future reassignment must lock every
affected User `FOR NO KEY UPDATE` in UUID order before changing the mapping; readers must continue
to revalidate the mapping after obtaining the relevant User lock.

Tenant dependencies retain their existing short, dependency-owned UOWs. Their locks protect only
the dependency's authorization decision and end when that UOW closes. A dependency-produced
organization context is not authorization for later handler work; each protected service
operation must authorize and access its resource within its own single UOW.

Implemented account profile and organization/member/invitation lifecycle writers acquire `FOR NO KEY
UPDATE` before validation or mutation, follow User → Organization → Invitation → Membership, sort
same-type rows by UUID, and lock the Organization before creating/restoring a Membership. The
explicit owner transfer locks both affected users, then changes both memberships atomically.
Self-service account deactivation locks the authenticated User `FOR NO KEY UPDATE`, then locks
every organization where that user has an active OWNER membership in UUID order, then locks all
memberships in UUID order. It verifies under those locks that each organization retains another
active OWNER backed by an active User before changing the local account status. No organization
membership or role is deleted or transferred. Account suspension/reactivation, organization
archival, privileged recovery, and identity reassignment remain unavailable; any future writer
must comply with this lock protocol before its capability is exposed. Do not add a separate
identity lock without a demonstrated requirement.

Do not add retries, arbitrary lock timeouts, isolation changes, or authorization caching. A
deadlock or other transient database failure must roll back the complete transaction, propagate
as a database failure, and must not be mapped to an authorization denial or not-found response.
Do not hold locks during network calls, AI inference, or long-running scan execution. These are
runtime row locks; no schema migration is required. SQLite tests remain useful for behavior but
do not establish lock correctness. PostgreSQL integration tests use independent connections,
events, bounded waits, and `pg_blocking_pids()` diagnostics to verify lock blocking, ordering,
writer-first observations, listing consistency, principal freshness, organization creation, and
rollback/lock release. The repository CI workflow runs the PostgreSQL marker separately; only actual CI results validate
that workflow. Protected scan persistence routes are mounted after route implementation and HTTP
integration tests. Local and CI PostgreSQL results must be recorded independently; route mounting
does not imply production security readiness. Future product routes must meet their own
implementation, validation, review, and deployment-specific requirements before exposure.

## Phase 2C milestone crosswalk

The overlapping API and security milestones are satisfied by one implementation and one
validation workstream; no duplicate routes or audits were added. Status below records this local
execution and does not assert a remote CI run or production readiness.

| Milestone | Status | Implementation and evidence |
| --- | --- | --- |
| 2C.4.6.2 | Complete | Personal ownership is assigned from the authenticated local principal and tested at service and HTTP layers, including cross-user and missing-scan equivalence. |
| 2C.4.6.3 | Complete | Organization role/action matrix, active and unavailable membership/scope cases, role changes, and local-role authority are covered by service and HTTP tests. |
| 2C.4.6.4 | Complete | Generic 401/403/404 response envelopes, relevant headers, and cross-scope non-disclosure are tested. |
| 2C.4.6.5 | Complete | Registered HTTP exception handlers and provider-claim negatives are tested, including bearer challenge behavior. |
| 2C.4.6.6 | Complete | Architecture and security documentation now state current behavior, capability limits, denial policy, and locking requirements. |
| 2C.4.7 | Complete | The protected scan API integration is the same six service-backed endpoints described under 2C.5. |
| 2C.4.8 | Complete (local validation) | Source-level authorization regression and PostgreSQL 17 integration tests passed; this is not a penetration test. |
| 2C.5 | Complete | The versioned API exposes the six protected persistence operations; routes use authentication and the scan service's single-UOW authorization boundary. |
| 2C.6 | Complete (local validation) | Full non-PostgreSQL and PostgreSQL suites, migration consistency, Ruff, Mypy, project validation, and OpenAPI checks passed. |

Validation in this execution: 336 API tests passed outside the PostgreSQL marker and 12 PostgreSQL
17 integration tests passed. Alembic reported revision `0557465b3944` as the sole head and
`alembic check` found no new upgrade operations. Ruff check/format, Mypy, repository validation,
and route/OpenAPI tests passed. No frontend files changed, so frontend build/lint/typecheck were
not run. The dedicated local test container was disposable; no development database was used.
The repository's separate remote CI workflow and deployment-specific security review were not run
or claimed.

There are no outstanding Phase 2C implementation items in this crosswalk. The
[Phase 2 roadmap](./phase-2-roadmap.md) records Phase 2D lifecycle implementation, validation, and
deferred requirements; do not claim the phase fully complete while account suspension/reactivation
and legitimate administrative recovery remain unavailable.
