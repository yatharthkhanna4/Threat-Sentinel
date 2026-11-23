# Architecture overview

## Current foundation

This repository is a pnpm/uv monorepo with a web application and one modular API application:

```text
Browser
  └── apps/web (Next.js App Router, TypeScript, Tailwind CSS)

apps/api (FastAPI, Pydantic Settings)
  ├── versioned HTTP routes (/api/v1)
  ├── shared configuration and structured logging
  ├── SQLAlchemy session layer and Alembic migrations
  └── modular application domains
        ├── identity
        ├── tenants
        ├── detection
        ├── intelligence
        ├── investigations
        ├── billing
        ├── audit
        └── integrations

PostgreSQL (optional local development dependency)
```

The API exposes liveness and readiness checks, authenticated account and organization lifecycle
operations, and scope-authorized scan-record persistence. The database URL remains optional at
startup: readiness reports `not_configured` when absent and checks connectivity when present.
Alembic migrations define identity, tenancy, scan persistence, account profile, and secure
invitation state.

## Identity and tenant boundaries

- `User` is an internal account with a stable UUID. `ExternalIdentity` maps a verified provider issuer and subject to that account; the `(issuer, subject)` pair is unique. Email is optional metadata, and a verified email is never used to merge accounts or identify a user.
- `VerifiedAccessTokenClaims` is a minimal, immutable internal contract for output from a
  successful verifier; it requires issuer, subject, audience, issuance time, and expiration, and
  excludes the bearer token and arbitrary provider claims. `AuthenticationProvider` is only a
  provider-neutral protocol and now returns this type. The type does not itself verify a token.
- Optional verifier settings are loaded out of band from the environment. The expected issuer,
  audience, trusted HTTPS JWKS URL, and explicit signing-algorithm allowlist must be configured as
  a complete set. These values are not accepted from tokens or requests, and configuring them
  alone does not activate authentication.
- `VerifiedUserContext` remains the Phase 2A internal issuer/subject and email-metadata contract
  used by identity and tenancy services; it is neither an untrusted request schema nor proof of
  token verification. `IdentityService.resolve_authenticated_principal()` resolves verified
  claims to an active local user and returns an immutable `AuthenticatedPrincipal` containing
  local and external identity IDs. Existing-user resolution locks the User `FOR SHARE` and
  revalidates the exact issuer/subject mapping before active-status validation and principal
  issuance. That principal is not an authorization grant.
- When a successfully verified issuer/subject pair is not known locally, identity resolution may
  create a local user and external identity mapping. This does not create an organization or
  membership; access still requires a separately established active local membership.
- `JwtAccessTokenVerifier` validates compact JWTs whose protected header has `typ: at+jwt`.
  It validates signatures only with compatible keys from the configured JWKS endpoint and only
  with configured asymmetric algorithms; issuer, audience, required time claims, subject, and
  optional email metadata are validated before returning `VerifiedAccessTokenClaims`.
  `get_current_principal` is a reusable FastAPI dependency that uses the provider to verify a
  bearer credential and resolves the claims to an active local identity. Protected scan routes use
  it. The reusable tenant dependency returns an `ActiveOrganizationContext` only after checking
  active local membership, but is not used as scan-service authorization input. Authentication
  configuration remains optional at startup; protected routes fail closed when it is unavailable.
  OIDC discovery and login flows are not implemented.
- `TrustedJwksKeyStore` rejects non-public DNS answers, pins HTTPS connections to validated IP
  addresses while retaining TLS hostname verification, does not follow redirects, uses three
  second connection/read timeouts, limits JWKS responses to 64 KiB, and caps cached keys using
  configuration. Refreshes are throttled, including requests for unknown key IDs.
- `Organization`, `OrganizationMembership`, and `OrganizationInvitation` are persisted separately from identity. A user may have memberships in multiple organizations. Organization creation atomically gives the creating active user an owner membership; resolving an identity alone creates no membership. Owner/admin/member/viewer are the roles. Management operations enforce a local role policy: owners can manage non-owners and invite admins; admins can manage members/viewers and invite members/viewers; only owners can transfer ownership or change organization lifecycle. This is a focused lifecycle policy, not a general fine-grained permissions framework.
- `OrganizationService` requires a `VerifiedUserContext`, resolves it to a local user by exact issuer and subject, then locks User → Organization → Membership `FOR SHARE` before checking active states. Membership lookup includes inactive rows and checks status after locking. A caller-supplied organization UUID alone is not an authorization check. Provider organization roles or claims are not consumed as application permissions.
- Organization listing locks User first, then all related Organization rows and Membership rows in sorted UUID order. It loads inactive memberships as well as active ones before locking; the User lock coordinates with protocol-compliant membership writers and prevents phantom memberships during result materialization.
- Organization creation locks the identity's User `FOR SHARE`, checks active status after acquiring the lock, and retains it through insertion of the Organization and initial OWNER Membership in one route-owned transaction. Pending invitations have a database-enforced unique key per organization and normalized email (lowercase and trimmed); terminal invitations do not block reissue.
- Invitation records bind to a specific verified external identity, store only a SHA-256 token hash, expire after seven days, and transition atomically with membership activation. The raw token is returned only by the authorized invitation-create response; there is no email delivery integration. Suspension revokes pending invitations; reactivation does not restore them.
- Lifecycle endpoints use server-side tenant scoping and role checks. Membership changes, ownership transfers, and explicit self-deactivation run under the canonical row-lock order and validate the active-owner invariant. A user may deactivate only their own active account; owner memberships and historical records remain. Organization suspension/reactivation is owner-controlled. There is no account suspension/reactivation or platform/organization recovery endpoint because no legitimate administrative control plane exists. See the [Phase 2D.2 account lifecycle assessment](./account-lifecycle-assessment.md).
- Owner-only organization archive/restore endpoints are implemented, and archive revokes pending invitations. Account export is available only for the authenticated principal. A durable tenant security-audit table records supported sensitive transitions; audit listing is owner/admin-only and tenant-scoped.
- `get_session()` is a request-scoped session resource, not a commit boundary. Mutating application operations must run inside `unit_of_work()`, which owns commit on success, rollback on exceptions, and session closure.
- `require_active_owner()` validates projected membership state before role/status changes and ownership transfer. Removed memberships cannot be changed directly; a valid invitation may reactivate an eligible non-owner membership. An owner may not be removed or demoted by the general membership endpoint; ownership changes use the explicit transfer operation.

These are application capabilities, not a production-ready authentication or authorization
system. Each protected organization-scan service operation independently authorizes its requested
scope and accesses scans in one UOW. The tenant dependency remains available, but its context is
not a grant for later service work. A verified external token produces verified claims; local
identity resolution produces an authenticated principal; local membership and role authorize
organization operations.

`packages/shared-contracts` is an intentionally empty starting point for future shared API contracts. It must not become a copy of backend business logic.

## Service authorization for the first product resource

The first resource is a Website/Domain Security Scan. Its model, scoped repository,
authorization-aware service, and protected persistence routes are implemented; a scanning engine
is not. A scan belongs to one logical scope: either a personal workspace or an organization workspace.
Personal operations lock the authenticated User `FOR SHARE`, revalidate the external identity
link, check active status, then access only that user's scans inside the same UOW. Personal scans
do not require organization membership. Organization scan operations lock User → Organization →
Membership `FOR SHARE`, check statuses after locks, and use the locally stored membership role
policy in the same UOW as scan access.
For the Phase 2 scan-record persistence routes, the approved matrix allows `OWNER`, `ADMIN`, and
`MEMBER` to create organization scan records, while `VIEWER` cannot; all four roles may read and
list those records. This does not grant access to future target management, scan execution,
findings, or evidence. The [Phase 3 architecture blueprint](./phase-3-architecture.md#authorization-matrix-and-api-boundary)
defines their separate approved permissions. See the
[Phase 2 authorization decision](./decisions.md#initial-website-domain-security-scan-authorization-service-and-protected-routes-implemented)
for the current persistence-route matrix and denial/transaction rules.

The server determines ownership and scope. Data access constrains resource ID and authorized scope
together. Domain exceptions distinguish missing or inaccessible resources/scopes (`404`), active
members denied an action (`403`), and a principal invalidated by local status or identity-mapping
revalidation (`401`). Domain services do not return HTTP statuses; the API layer maps these
outcomes to the generic HTTP error envelope without exposing authorization details. The service
performs authorization and scan access in one unit of work with PostgreSQL row locks. Tenant
dependency checks have separate, short UOWs; their resulting context is not authorization for later
handler resource access.
The six scan persistence endpoints are mounted under `/api/v1`: `POST`/`GET` `/scans`,
`GET` `/scans/{scan_id}`, `POST`/`GET` `/organizations/{organization_id}/scans`, and
`GET /organizations/{organization_id}/scans/{scan_id}`. Scan execution and analysis remain
unimplemented.
See the
[authorization transaction and concurrency protocol](./decisions.md#authorization-transaction-and-concurrency-protocol-implemented-postgresql-integration-tests).

## Concurrency validation status

The PostgreSQL 17 integration tests exercise independent sessions and connections, deterministic
events, bounded waits, and PostgreSQL blocking diagnostics. In addition to scan authorization
locking and organization creation, they cover concurrent identity provisioning, membership
administration, ownership transfer, and invitation acceptance. The SQLite suite validates
application behavior but is not evidence of PostgreSQL row-lock behavior. Local validation does
not imply remote CI success, production deployment, or readiness. See the
[Phase 2 roadmap](./phase-2-roadmap.md) for current lifecycle capabilities and deferred controls.

## Design direction

- Keep the initial backend as a modular monolith with clear application boundaries. Extract services only when measured scale or independent operational requirements support doing so.
- Keep HTTP contracts versioned and separate from persistence models.
- Keep the database optional for health-only startup; database-backed operations require a configured database and applied migrations.
- Keep external authentication at a provider adapter boundary, while local user state, organization membership, and authorization remain application-owned.
- Introduce provider-neutral adapters at actual integration boundaries, including future local/cloud inference. No AI provider is selected or integrated.
- Treat tenancy, privacy, retention, authorization, and auditability as architecture requirements before adding sensitive workflows.

## Phase 3 architecture blueprint

The [Phase 3 architecture, threat model, and implementation blueprint](./phase-3-architecture.md)
records nine product-owner-approved architecture decisions and the detailed proposed design for
exact-host DNS TXT verification, controlled outbound networking, a PostgreSQL-backed queue, an
isolated Python worker, and read-only detection modules. The Phase 3A specification is formally
approved and closed; Phase 3B is authorized and underway. Phase 3B.1 hostname canonicalization is
implemented and pending final acceptance. Phase 3B.2 organization target and challenge persistence
and Phase 3B.3 server-side organization-target DNS TXT verification are implemented. The verifier
uses the system-configured DNS resolver and bounded exact TXT matching, and atomically consumes
challenges before marking targets verified. No target API or challenge rate limits are implemented;
enforce rate limits before exposing challenge operations.

The project owner approved **IP Destination Policy v1** on `2026-11-24`; its snapshots, normalized
policy artifact, pure evaluator, and tests are implemented. Phase 3B.4.1–3 also implement immutable
DNS-resolution models and secure dual-stack resolution. Phase 3B.4.4 implements a one-shot pinned
HTTP/HTTPS transport with strict bounded HTTP/1.1 parsing and caller-owned scan accounting. These
capabilities do not add a public target route, scanner, queue, worker, or production deployment
configuration. Production-provider egress review remains required before deployment. The approved
resolver and outbound requirements are described in the
[Phase 3 architecture proposal](./phase-3-architecture.md#dns-aaaa-resolution-proposal) and
[IP-policy section](./phase-3-architecture.md#explicit-ipv4ipv6-policy).

## Planned, not implemented

Protected scan persistence and the lifecycle API described in the
[Phase 2 roadmap](./phase-2-roadmap.md) are implemented. Scan execution and analysis, OIDC
discovery and browser login flows, invitation email delivery, account suspension/reactivation,
privileged and organization recovery, a general fine-grained permissions framework, detection,
risk assessment, AI inference, investigations, intelligence feeds, billing, developer
integrations, frontend lifecycle UI, and production deployment
remain future capabilities.
