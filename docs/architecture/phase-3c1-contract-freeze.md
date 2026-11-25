# Phase 3C.1 — Contract and Decision Freeze

Status: **DESIGN-FREEZE ACCEPTED WITH FOLLOW-UP**

This specification finalizes the Phase 3C.1 contract and decision baseline. It describes
implementation contracts and integrity requirements only. It does not implement persistence,
migrations, queueing, workers, scanner execution, detection, public execution routes, or
retention jobs.

This specification is additive to the approved [Phase 3 architecture](./phase-3-architecture.md)
and the existing [Phase 2 scan authorization decision](./decisions.md#initial-website-domain-security-scan-authorization-service-and-protected-routes-implemented).
No repository behavior is changed by this document.

## 1. Freeze status and baseline

The following baseline decisions are preserved:

1. **Organization targets only initially.** Personal executable scans are prohibited. Existing
   personal `security_scans` records remain valid.
2. **One parent, one target, multiple runs.** A parent may receive multiple logical runs, and
   those runs identify the same parent target once a target relationship is established.
3. **Principal-scoped idempotency.** The stable local authenticated user ID is the principal, and
   admission is keyed by that principal, an operation namespace, and a SHA-256 hash of a
   deterministic normalized payload.
4. **90/30/365-day provisional defaults.** Terminal-run data is retained for 90 days, no-run
   parents receive a 30-day closure period, and audit events receive a 365-day retention baseline.
   These periods remain provisional and require legal, contractual, and production review.
5. **Legacy compatibility.** Existing `security_scans` rows and Phase 2 ownership/creator
   constraints remain valid. `security_scans.target_id` is nullable and must not be backfilled.

### 1.1 Accepted scope

Phase 3C.1 includes:

- architecture decision freeze;
- pure Python contract and lifecycle definitions;
- versioned TypeScript DTO exports;
- deterministic payload and key-hash test specifications;
- contract validation and compatibility tests;
- documentation updates.

Phase 3C.1 excludes:

- database migrations;
- SQLAlchemy/ORM model or relationship changes;
- database connections or repository persistence;
- public execution endpoints;
- queue dispatch or queue table behavior;
- worker claims, leases, heartbeats, fencing, or reapers;
- scanner execution or the pinned transport;
- detection modules or finding production;
- retention purge implementation;
- backup/restore reconciliation.

## 2. Existing contracts that do not change

The existing Phase 2 public scan-record routes and response shapes remain unchanged:

- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `POST /api/v1/organizations/{organization_id}/scans`
- `GET /api/v1/organizations/{organization_id}/scans`
- `GET /api/v1/organizations/{organization_id}/scans/{scan_id}`

The existing scan model remains exactly one of:

- personal: `owner_user_id` set, `organization_id` null, and
  `owner_user_id == created_by_user_id`;
- organization: `organization_id` set and `owner_user_id` null.

The existing Phase 2 authorization matrix remains authoritative:

- organization scan creation: OWNER, ADMIN, MEMBER;
- organization scan read/list: OWNER, ADMIN, MEMBER, VIEWER;
- personal list/read: only the owning principal;
- personal creation: server-assigned principal ownership.

These persistence routes must not gain execution, findings, evidence, cancellation, or run-status
behavior. Any future route for those capabilities must remain separately versioned and approved.

The Alembic migration head for this freeze baseline is
`1c2f78b9d640` (`Add organization targets and TXT verification`).

## 3. Target association and tenant integrity

`security_scans.target_id` is the authoritative nullable target association. It is distinct from
every run snapshot and is used to establish a parent-to-target relationship.

### 3.1 Association rules

The following rules are mandatory:

- A personal `security_scans` row must have `target_id IS NULL`.
- An organization `security_scans` row may have `target_id NULL` for a legacy or nonexecuted record.
- When `target_id` is non-null:
  - `organization_id` must be non-null;
  - `security_scans.organization_id` must equal
    `security_targets.organization_id`;
  - the target must be organization-owned and verified when establishing an executable run.
- A legacy record may remain targetless. It must not receive a fabricated target or run.
- Every run must use the parent organization and target scope from the authoritative association.
- A target association cannot be reassigned once a run relationship exists.

The precise database transition is intentionally not implemented in this phase. The persistence
design freeze requires a future migration to enforce these invariants without rewriting or deleting
legacy Phase 2 data.

### 3.2 Composite uniqueness and foreign keys

The future persistence migration must provide the required uniqueness for composite tenant-aware
foreign keys:

- `security_scans(organization_id, id)` must be unique for organization rows.
- `security_targets(organization_id, id)` must remain unique and is already modeled by
  `uq_security_targets_organization_id`.
- `organization_memberships(organization_id, id)` and existing organization target uniqueness
  remain unchanged.

The future dependent relationships must use composite foreign keys where tenant scope is carried:

- parent-to-target:
  `security_scans(organization_id, target_id)` →
  `security_targets(organization_id, id)`;
- run to parent:
  `scan_runs(organization_id, scan_id)` →
  `security_scans(organization_id, id)`;
- run to target:
  `scan_runs(organization_id, target_id)` →
  `security_targets(organization_id, id)`;
- run to its parent and target:
  `scan_runs(organization_id, scan_id, target_id)` →
  `security_scans(organization_id, id, target_id)`.
- challenge references remain covered by the existing composite target/challenge foreign key.

The future `security_scans` table must expose an additional unique key for
`(organization_id, id, target_id)` if it is used as the parent/key-side target reference. The
three-column foreign key from `scan_runs` is then the authoritative database relationship that
requires `scan_runs.target_id` to equal the target already associated with the parent
`security_scans` row. It is not sufficient to define separate foreign keys on `scan_id` and
`target_id`; they would permit a run to reference a target owned by the same organization but
different from its parent's target.

An ordinary SQL `CHECK` cannot compare values across `security_scans` and `scan_runs`. Cross-table
equality must be enforced by the composite foreign key above. A separate composite target foreign
key must still enforce organization ownership of the run target.

Executable runs require non-null `scan_runs.organization_id` and `scan_runs.target_id` values.
Legacy and no-run `security_scans` rows may retain nullable `target_id`, but a personal
`security_scans` row must never receive a target association. Target association remains prohibited
for personal scopes regardless of future target scope expansion.

Direct foreign keys may be used only when the target table row is tenant-independent. Every
dependent repository lookup must still constrain both the resource ID and the authorized tenant,
even if a database constraint is present.

The following database checks are mandatory at the future persistence boundary:

- `target_id IS NULL OR organization_id IS NOT NULL`;
- personal scan scope plus a target is invalid;
- organization target ownership matches the parent organization;
- run target and parent target associations agree;
- attempt, finding, and evidence records reference a run that belongs to the same organization;
- evidence attached to a finding belongs to the same run.

Foreign keys for durable scan relationships use `RESTRICT`. Retention code, never a generic
parent-cascade rule, owns the ordered deletion of run dependents.

### 3.3 Immutable run target snapshot

When an execution relationship is first established, the run must preserve an immutable snapshot:

- stable target ID;
- organization ID;
- canonical exact hostname;
- target verification status at run admission;
- target `verified_at` value;
- target-verification policy version;
- snapshot or policy provenance needed to reproduce target interpretation.

The snapshot must not contain:

- ephemeral DNS A or AAAA resolution addresses;
- CNAME answers;
- resolver response bodies;
- TXT challenge plaintext or challenge hashes;
- transient DNS resolution results.

The snapshot is immutable after run creation. Subsequent target hostname changes, verification
state changes, challenge rotation, DNS re-resolution, or policy refresh must not rewrite historical
runs. New runs may record a new snapshot under the same parent only if the target relationship
remains valid and the target is not reassigned.

## 4. Parent lifecycle and retention

### 4.1 Internal no-run closure

The existing public `SecurityScan`/`ScanResponse` representation does not gain a state or lifecycle
field. No-run closure is an internal persistence concept that may be materialized only in future
request/run implementation.

A parent receives `no_run_closed_at` only when it is explicitly terminal and no
`scan_runs` record has ever been associated with it. `no_run_closed_at` is a UTC timestamp set
atomically with the bounded closure reason. It must not be inferred from parent creation age.

The 30-day retention clock applies **only** to parents for which:

- `no_run_closed_at` is non-null;
- no `scan_runs` record has ever existed for the parent;
- no record remains that blocks referential deletion.

Age alone does not close a parent. Queued or otherwise recoverable work is never purged and must
not be represented only by an old parent row.

### 4.2 Closure reason

The internal closure reason is a bounded enum. Initial values are:

- `cancelled`;
- `expired`;
- `administratively_closed`.

`administratively_closed` is reserved for separately approved operational correction and is not
authorized for ordinary API admission. An ordinary implementation must define who may produce this
reason before exposing such an operation.

No-run closure is not redefined as the absence of a run at cleanup time. The existence of any
associated run is decisive and prevents no-run retention semantics.

### 4.3 Parent/run retention

The provisional retention defaults are:

- terminal runs and their attempts, findings, and normalized evidence: 90 days from the run's
  authoritative `terminal_at`;
- no-run parents: 30 days from `no_run_closed_at`;
- audit events: 365 days from the audit event timestamp.

The defaults are provisional. They do not establish legal compliance or current repository settings.

A parent is retained while either:

- at least one associated run remains outside terminal retention;
- at least one active, queued, cancel-requested, leased, or otherwise recoverable run exists;
- terminal-run dependent records remain retained;
- a referential dependency prevents safe deletion.

A newer run does not extend an older run's 90-day period. Parent eligibility is reevaluated after
any run-dependent cleanup. Purge behavior remains excluded from 3C.1 and belongs in 3G/3H.

The 30-day clock must not delete a parent when a run is added later or a run relationship exists,
even if the run became associated after the parent closure marker was set. A future transition
must reject run creation after no-run closure or clear the closure as a separately audited
administrative operation.

## 5. Idempotency contract

### 5.1 Principal and operation identity

The stable local `User.id` UUID is the idempotency principal identity. External issuer/subject
strings, email, organization role, and request IDs are not principal identity.

The unique idempotency identity is:

```text
(principal_user_id, server_resolved_organization_scope, operation_namespace, idempotency_key_hash)
```

`server_resolved_organization_scope` is a stable organization UUID for organization-scoped
operations or an explicit personal/null scope for personal operations. It is resolved from the
authenticated route/context and server authorization state; it is never derived from or accepted
as client ownership scope.

`operation_namespace` is the single versioned operation identity. It includes the operation and
must not be accompanied by a separate redundant operation field. Initial values are:

- `security-scans/v1/run-admission`
- `security-scans/v1/run-cancellation`

The principal ID remains mandatory and separate from organization scope. A future 3C.4/3C.5
database implementation may persist this tuple, but it must not persist the plaintext key or
normalized payload.

### 5.2 Deterministic payload canonicalization

The normalized payload for hashing is the JSON-compatible operation payload after removing all
transport metadata and all server-owned or authorization-owned fields.

The 3C.1 ThreatSentinel Canonical JSON Profile (TCJP-1) is:

1. JSON objects contain only string keys.
2. Both object keys and string values are normalized to Unicode NFC before serialization.
3. Object keys are checked and rejected if duplicate before or after NFC normalization.
4. Invalid Unicode sequences, including lone UTF-16 surrogates and invalid UTF-8 sequences, are
   rejected for keys and values.
5. Object keys are sorted using JCS-compatible deterministic key ordering after NFC normalization.
6. JCS-compatible serialization is then applied with UTF-8 output and no insignificant whitespace.
7. Floating-point JSON numbers are prohibited.
8. Integer values are restricted to interoperable safe integers in the inclusive range
   `-9007199254740991` through `9007199254740991`. Larger quantities must use explicitly named
   strings in the contract rather than JSON numbers.
9. JavaScript `null`, `undefined`, `NaN`, and `Infinity` are prohibited.
10. Unknown fields are prohibited at the contract boundary.
11. The profile forbids JSON number exponent output because TCJP-1 payloads use only safe integers
   or prohibited floating-point values.

TCJP-1 is ThreatSentinel-specific and is not defined as an endorsement or general replacement of
RFC 8785/JCS. It uses NFC preprocessing for keys and values, duplicate-key rejection after NFC
normalization, invalid-Unicode rejection, and JCS-compatible key and string serialization with
the numeric restrictions above.

The payload must contain no owner ID, creator ID, organization role, authorization result,
principal, request ID, current state, attempt ID, worker ID, lease, or execution context. These
values are server-derived and must not affect the hash.

The canonical payload is the exact operation input contract. The operation namespace and principal
identity are separate hash components and must not be duplicated into the canonical payload merely
to change the key hash.

### 5.3 Hash requirements

Both values are hashed before persistence or logging:

- normalized payload hash: SHA-256 of the canonical payload UTF-8 bytes;
- idempotency key hash: SHA-256 of the exact UTF-8 idempotency key bytes.

Plaintext idempotency keys and plaintext normalized payloads must never be persisted or logged.
Only 64-character lowercase hexadecimal SHA-256 values are stored.

The key format and entropy requirements are:

- the client supplies one opaque key;
- keys must contain at least 128 bits of effective entropy;
- future HTTP validation must reject omitted, blank, control-character, or overlength keys.

The exact maximum key length and entropy-validation mechanism remain implementation details for
3C.2/3C.4 and must not weaken the no-plaintext rule.

### 5.4 Replay and conflict behavior

For a live idempotency identity:

- **same key + same normalized payload:** replay the original admitted logical operation or return
  the same operation result, without creating a second parent or run;
- **same key + different normalized payload:** return a stable conflict outcome and create neither
  a parent nor a run.

The pure contract model must distinguish replay, conflict, and new admission without exposing
ownership or authorization context.

Concurrent first submissions are database-concurrency behavior and belong to 3C.4/3C.5. Pure
contract/hash tests in 3C.1 test canonicalization, hash stability, replay, and conflict decisions
only.

### 5.5 Lifetime

For `security-scans/v1/run-admission`, an idempotency identity has a provisional replay period of
**90 days beginning at successful admission**. The associated logical run prevents key expiry while
it remains nonterminal, regardless of whether 90 days from admission have elapsed.

The identity becomes eligible for expiry only when both conditions hold:

- the associated logical run is terminal; and
- at least 90 days have elapsed since the successful admission timestamp.

Terminal and nonterminal are evaluated from the logical run, not from attempt state or run
retention age. A queued, running, or cancel-requested run keeps the identity live. Retrying an
attempt does not change replay eligibility.

Key expiry is independent of business-data retention. Expiring or deleting the key hash record
must not expire, delete, or extend the run, parent, results, attempts, findings, or evidence. The
run remains subject to its own 90-day terminal-run retention, and the parent remains subject to
its independent no-run or run relationships.

After expiry, the key hash record may be deleted or archived and reusing that key may create a new
operation. Reuse is never permitted to create a duplicate admission while the original logical run
remains nonterminal: before starting a new operation, persistence logic must recheck the associated
run state and refuse or defer duplicate-key reuse until that original run is terminal and the
expiry conditions above are satisfied.

For `security-scans/v1/run-cancellation`, cancellation has its own operation namespace and replay
semantics. A live cancellation identity may replay the cancellation outcome or terminal resolution
for the same run. Cancellation-key expiry follows the same associated-run rule: it must not expire
while the run remains nonterminal. It becomes eligible for expiry only after the run is terminal
and at least 90 days have elapsed since the successful cancellation admission, subject to the
database implementation's independent record lifecycle.

Key expiry behavior and reconciliation are database implementation details and remain deferred to
the persistence/concurrency phases. The 90-day replay periods are provisional with the retention
defaults and are not yet production-approved.

## 6. Run lifecycle

### 6.1 States

The logical run state enum is frozen for contracts:

- `queued`
- `running`
- `cancel_requested`
- `succeeded`
- `partial`
- `failed`
- `cancelled`

No other run state is public in this freeze. Queue implementation, leases, attempts, heartbeats,
and stale-worker recovery are not implemented.

### 6.2 Valid transitions

Valid transitions are:

- `queued -> running`
- `queued -> cancel_requested`
- `running -> cancel_requested`
- `running -> succeeded`
- `running -> partial`
- `running -> failed`
- `cancel_requested -> cancelled`
- `cancel_requested -> succeeded`
- `cancel_requested -> partial`
- `cancel_requested -> failed`
  - no direct bypass of `cancel_requested`

Terminal states are `succeeded`, `partial`, `failed`, and `cancelled`.

An attempted transition outside this table is contract-invalid. A terminal state is immutable.
Only a separately documented administrative correction, if later approved, may alter terminal
history; no such authority is granted in Phase 3C.1.

### 6.3 Cancellation race

`cancel_requested` resolves according to which terminal operation wins:

- to `cancelled` when cancellation is committed/recognized before terminal result acceptance and
  no terminal result has already won;
- to `succeeded`, `partial`, or `failed` when a terminal operation is accepted under the
  later queue/worker concurrency rules.

The exact worker fencing and race transaction belong to Phase 3D. The contract preserves only the
nonterminal-to-terminal outcome and requires cancellation not to erase existing observations.
There is no direct `running -> cancelled` or `queued -> cancelled` transition in the 3C.1 contract;
cancellation first enters `cancel_requested`, and only that state is resolved to `cancelled` or
another terminal state.

### 6.4 Authoritative terminal timestamp

`terminal_at` is the authoritative UTC timestamp for run retention and is set exactly once when a
run first enters a terminal state.

After `terminal_at` is set:

- it is immutable;
- later retries, heartbeats, or observations cannot change it;
- cancellation or a terminal result cannot overwrite it;
- per-run retention eligibility uses this timestamp;
- a sibling run does not change it.

`started_at`, `updated_at`, `cancel_requested_at`, and attempt timestamps are nonauthoritative for
retention unless separately frozen by the queue contract.

### 6.5 Attempts and retries

Retries append `scan_attempts` to the same logical run. A retry increments attempt provenance,
creates a new attempt record, and does not create a new run.

A retryable attempt failure:

- appends a new attempt event under the existing run;
- does not change the logical run state;
- remains eligible for retry while the retry budget remains;
- does not set `terminal_at`;
- uses the same run ID and target snapshot;
- does not create a second run or finding record.

The retry budget, scheduling, and next-attempt claim behavior are queue/worker implementation
details. A retryable attempt failure is not a formal state transition and does not use a
`running -> running` transition. The run remains `running` by unchanged state while eligible for
the next attempt. If cancellation is already active, the run remains `cancel_requested` and no
new attempt is scheduled.

When the retry budget is exhausted, the run transition to `failed` is implemented and proven in
the later queue/worker phase. Terminal state and `terminal_at` behavior belong to this contract,
but retry scheduling, backoff, and claim implementation do not.

An attempt that fails while `cancel_requested` must not start or schedule a retry. Its run remains
eligible only to resolve through `cancel_requested -> cancelled`, or to a terminal result already
recognized as the race winner. Queue and worker fencing details are excluded from 3C.1.

## 7. Findings and evidence

### 7.1 Findings are immutable observations

A finding is an immutable, versioned observation scoped to exactly one logical run.

An initial finding contract contains:

- stable finding ID;
- run ID;
- target snapshot reference;
- stable fingerprint;
- scanner ID and version;
- check/rule ID and version;
- evidence schema ID and version;
- title;
- normalized summary;
- severity;
- confidence;
- remediation guidance;
- first observed UTC timestamp;
- last observed UTC timestamp;
- evidence references.

Findings do not receive a triage lifecycle in this phase. Open, resolved, ignored, accepted,
reopened, and similar lifecycle states are unapproved and must not appear as contract fields.
Historical comparison is descriptive: new, persistent, or no-longer-observed findings are derived
from run-to-run fingerprints rather than mutating prior findings.

Finding fingerprints are derived from:

- scoped canonical target identity;
- stable check/rule identity;
- normalized affected component.

Timestamps, attempt IDs, evidence values, and volatile worker IDs must not participate in a
finding fingerprint.

### 7.2 Evidence structure

Evidence is a bounded normalized observation with an explicit schema.

An initial evidence contract contains:

- evidence ID;
- run ID;
- optional finding ID;
- evidence schema ID;
- evidence schema version;
- source check/rule ID;
- source check/rule version;
- normalized kind/type;
- observed-at UTC timestamp;
- allowed structured normalized value;
- provenance.

Evidence may reference one run and, if attached to a finding, must belong to that same run.

A permitted evidence value is one of:

- a scalar string, safe interoperable integer, or boolean;
- a flat array of strings, safe integers, or booleans;
- a root flat object containing only strings, safe integers, booleans, or flat arrays of those
  scalar types.

The permitted structural shapes are therefore exactly:

```text
scalar
flat array
root flat object -> scalar or flat array
```

Arrays may not contain arrays or objects. Objects may not occur beneath arrays or beneath another
object. The maximum structural nesting is one container level beneath the root object or top-level
array. An evidence scalar has zero container levels.

Safe integers are restricted to the inclusive range `-9007199254740991` through
`9007199254740991`; integers outside that range must use an explicitly named string representation.
Nested objects, nested arrays, arbitrary classes, binary blobs, floating-point values, `NaN`,
`Infinity`, and unbounded JSON are prohibited.

### 7.3 Sensitive-data exclusions

Evidence must never contain:

- raw HTTP response bodies;
- complete or partial bearer, session, cookie, API, or TXT-challenge values;
- authentication or authorization headers;
- credentials or password material;
- private keys or secrets;
- server traces or raw exception text;
- arbitrary remote response content;
- DNS resolution addresses or CNAME answers;
- full query-bearing URLs where a redacted component would suffice.

Raw headers, cookies, bodies, challenge plaintext, and volatile network observations are
prohibited rather than redacted after persistence.

### 7.4 Evidence limits

The structural evidence allowlist is frozen now. Structural validation is mandatory in contract
validation: evidence values must use only a scalar, a flat array, or a root flat object whose values
are scalars or flat arrays. Nested objects and nested arrays, binary values, arbitrary JSON,
floating-point values, sensitive fields, and unknown schemas are rejected.

Exact numerical limits are deliberately deferred until approval before 3C.3. The outstanding
items are:

- maximum evidence value bytes;
- maximum number of evidence records per run;
- maximum number of evidence records per finding;
- maximum string length;
- maximum object key count;
- maximum array length;
- maximum evidence nesting depth (fixed by the structural allowlist at one container level beneath
  a root object or top-level array);
- maximum aggregate evidence payload per run;
- representation rules for truncation and over-limit rejection.

Contract validation must enforce the structural allowlist now. It must not claim to enforce
numerical limits that have not been approved. Numerical limits must be represented by explicit
constants or configuration only after approval; placeholder validators that accept unbounded JSON
or otherwise defer structural validation are prohibited.

## 8. Python contract versioning

The Python contracts are descriptive Pydantic models. The `V1` suffix identifies the contract
schema version; it does not identify a Pydantic library version or imply that Pydantic itself is
part of the wire contract.

Suggested public schema names are:

- `ScanContractV1`
- `SecurityScanRefV1`
- `ScanRunV1`
- `ScanAttemptV1`
- `ScanRunLifecycleV1`
- `ScanFindingV1`
- `ScanEvidenceV1`
- `ScanTargetSnapshotV1`

Internal, non-client contracts may exist for persisted idempotency hashes and retention metadata,
but they must not be part of public Python or TypeScript client DTO exports unless a concrete
consumer requires them. Transport idempotency-key input is a client-supplied opaque key envelope
or header contract. Persisted idempotency metadata contains only key/payload hashes and server-owned
timestamps; it is an internal representation and must never expose plaintext keys or payloads.

Names containing `V1` freeze the in-repository contract package. Python modules and HTTP schemas
remain versioned separately; `V1` names must not imply that a public route exists.

Python contract rules:

- use `BaseModel`;
- use `ConfigDict(extra="forbid", frozen=True, strict=True)`;
- use explicit enums and UUID types;
- reject unknown fields;
- reject nonfinite floats;
- reject cross-scope ownership data in client-supplied request contracts;
- use immutable snapshot objects where the contract represents historical state;
- use separate request and response contracts;
- keep database models and Pydantic DTOs independent.

Client request contracts must not accept or expose:

- `owner_user_id`;
- `created_by_user_id`;
- `organization_id` as an ownership grant;
- `actor_user_id`;
- role state;
- target verification state supplied by the client;
- execution context;
- worker or attempt IDs;
- lease or fencing values;
- finding or evidence server IDs supplied for relationship forging;
- lifecycle state transitions supplied as write context.

Only server-produced response contracts may expose run, attempt, finding, and evidence identities.
These response contracts remain descriptive and must not imply that a route is available.

## 9. TypeScript contract exports

[packages/shared-contracts/src/index.ts](../../packages/shared-contracts/src/index.ts) is the
corresponding future package export surface. It is not an implementation step for Phase 3C.1.

The package should export corresponding DTO names:

- `ScanContractV1`
- `SecurityScanRefV1`
- `ScanRunV1`
- `ScanAttemptV1`
- `ScanRunLifecycleV1`
- `ScanFindingV1`
- `ScanEvidenceV1`
- `ScanTargetSnapshotV1`

The transport idempotency-key input is represented as a transport/header contract or a
request-local field, not as a DTO containing persisted hash metadata. Persisted SHA-256 key and
payload hashes, replay expiry timestamps, and retention metadata are internal server state and are
not exported as public TypeScript DTOs.

TypeScript contracts must be:

- readonly;
- discriminated unions where replay/conflict/lifecycle state differs;
- readonly fields provide compile-time TypeScript guarantees only;
- runtime validation is not provided by readonly types and requires a separately approved runtime
  validator;
- independent of SQLAlchemy models;
- non-operational: no dispatch, worker, transport, scanner, or persistence API surface.

The existing `@threat-sentinel/shared-contracts` package remains an intentionally thin contract
package. It must not become a copy of backend authorization or execution business logic.

## 10. Contract test boundaries

Phase 3C.1 pure contract tests cover:

- strict unknown-field rejection;
- frozen/immutable models;
- valid and invalid run transitions;
- terminal-state timestamp behavior;
- finding/evidence structure and sensitive-field rejection;
- organization-personal target mismatch rejection;
- target snapshot immutability;
- legacy nullable target compatibility;
- TCJP-1 payload canonicalization with NFC preprocessing and JCS-compatible serialization;
- TCJP-1 rejection of duplicate raw keys, duplicate keys created by NFC normalization, and invalid
  Unicode sequences;
- byte-identical Python and TypeScript TCJP-1 fixture output;
- Python/TypeScript parity fixtures for NFC-normalized Unicode key collisions;
- stable SHA-256 key and payload hashes;
- plaintext key omission;
- same-key/same-payload replay;
- same-key/different-payload conflict.

Database concurrency, unique-row, replay-row, and conflict-row behavior remains Phase 3C.4/3C.5
and requires PostgreSQL tests. Contract tests must not open a database connection.

Phase 3C.1 contract tests must also demonstrate that:

- existing Phase 2 response contracts remain unchanged;
- personal and organization ownership rules are not relaxed;
- no public execution endpoint is described as available;
- no code promises execution before the queue/worker phases.

## 11. Audit contract

The future execution/persistence implementation must use the existing
`SecurityAuditEvent` transaction convention. Audit action coverage must include separately
identified decisions for:

- run admission success and replay;
- idempotency conflict;
- target mismatch or unverified target rejection;
- personal-scope execution rejection;
- run cancellation request and cancellation outcome;
- terminal transition/outcome event and `terminal_at` assignment for `succeeded`, `partial`,
  `failed`, or `cancelled`;
- terminal timestamp reconciliation;
- run-dependent cleanup;
- parent no-run closure;
- parent deletion eligibility and deletion;
- key expiry or key reuse.

Audit details must not contain plaintext idempotency keys, normalized payload plaintext, target
challenge plaintext, DNS responses, response bodies, cookies, credentials, or secrets.

Audit coverage implementation remains Phase 3C.4/3C.5 and later retention phases. This phase freezes
the action-family requirement only.

## 12. Design-freeze acceptance matrix

| Item | Status | Phase 3C.1 decision |
|---|---|---|
| Organization targets only | ACCEPTED | Personal executable scope rejected; existing personal records preserved |
| One parent/one target/multiple runs | ACCEPTED | Parent-to-target is nullable and immutable once runs exist |
| Principal-scoped idempotency | ACCEPTED WITH FOLLOW-UP | Stable local user ID, operation namespace, SHA-256 key/payload hashes; exact key lifetime proposed as provisional 90 days |
| 90/30/365 retention | ACCEPTED AS PROVISIONAL | Freeze defaults; no purge implementation |
| Legacy nullable target association | ACCEPTED | No backfill or deletion of legacy Phase 2 records |
| Tenant composite integrity | ACCEPTED | Composite parent/run/target uniqueness and foreign keys required |
| Target snapshot | ACCEPTED | Identity and verification context immutable; no transient DNS addresses |
| Parent no-run closure | ACCEPTED WITH FOLLOW-UP | Internal `no_run_closed_at` and bounded reason; public API unchanged |
| Run lifecycle | ACCEPTED | Frozen states and transitions; terminal `terminal_at` |
| Cancellation outcome | ACCEPTED | `cancel_requested` may resolve to a terminal state based on winning operation |
| Retries | ACCEPTED | Append attempts to the same logical run |
| Findings | ACCEPTED WITH FOLLOW-UP | Immutable, versioned observations; no triage lifecycle |
| Evidence structure | ACCEPTED WITH FOLLOW-UP | Flat/bounded normalized values only; exact limits unresolved |
| Python contracts | ACCEPTED | Strict, frozen, versioned Pydantic contracts; no ownership fields in requests |
| TypeScript DTOs | ACCEPTED | Strict readonly exported V1 DTO names; descriptive/non-operational |
| Database implementation | EXCLUDED | No ORM, migration, repository, or database-concurrency implementation |
| Queue and worker | EXCLUDED | No dispatch, lease, heartbeat, fencing, reaper, or worker implementation |
| Public execution API | EXCLUDED | No execution endpoints or status/result route changes |

## 13. Outstanding decisions

The following decisions remain approval items, and this document does not silently convert them
into completed implementation:

1. **Evidence numerical limits:** approved before 3C.3.
2. **Idempotency key lifetime:** exactly 90 days is proposed and remains provisional.
3. **Idempotency key length/entropy validation:** format and exact max length must be approved in
   the persistence phase.
4. **Finding severity/confidence rubric:** exact versioned rubric remains required before
   detection findings are emitted.
5. **No-run `administratively_closed` authority:** actor and operation policy remain unresolved.
6. **Target lifetime/reverification policy:** challenge TTL and target expiry/reverification remain
   Phase 3B follow-ups.
7. **User-initiated deletion semantics:** deletion scope and actor policy remain unresolved.
8. **Backup/restore reconciliation:** external authority and tested restore behavior remain
   production decisions.
9. **Audit retention implementation:** 365 days is provisional and implementation belongs to later
   retention/audit work.
10. **Purge implementation details:** batch, restart, and dependency order remain Phase 3G/3H.

## 14. Final freeze boundary

This specification is the Phase 3C.1 design freeze. It changes no current runtime behavior and
does not authorize migration, persistence, queue, worker, scanner, detection, or public execution
implementation.

**Implementation has not begun.**
