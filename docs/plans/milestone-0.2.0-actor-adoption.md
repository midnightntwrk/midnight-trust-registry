# 0.2.0 actor adoption plan

Status: proposed implementation plan. This is not a deployment or production
conformance claim. The first target is a self-hosted local Ledger 8 registry;
the Ledger 9 migration is tracked separately in #292.

## Outcome and scope

An operator can start from a fresh, pinned install, authenticate distinct
applicant and maintainer actors, complete one issuer application through a
finalized local registry decision, and verify that decision with an independent
client. The same protocol must support verifier and auditor applications; a
UI role switch or fixture workspace is not an authentication mechanism.

The critical path is the actor host (#219), independently authenticated
finality and recovery (#220), the existing signed-intent acceptance issue
(#77), and the real use-case tests (#58, #59, #78). Existing UI and browser
coverage (#254, #260, #261) remains separate from deployed acceptance.
This plan does not silently move unfinished 0.1.0 acceptance issues into
0.2.0 or close them based on simulator evidence.

## Authentication and authorization

1. **Identity:** phase 0 accepts a self-certifying long-form off-chain
   `did:midnight` document for sign-in. Resolve and verify the encoded state
   against its short-form DID; do not mistake a caller-supplied document for
   ledger freshness or revocation. A later, explicit on-chain mode must resolve
   the current, non-deactivated DID document against an authenticated ledger
   source. DID possession alone grants no registry role in either mode.
2. **Request authentication:** the host issues a random, one-use, short-lived
   challenge bound to origin, registry deployment, actor DID, intended
   audience, and operation. Verify the response against a current DID
   `authentication` method. A caller-supplied DID or demo header is not proof.
   A session may carry this verified identity for navigation and read access,
   but has bounded lifetime, rotation, logout, and CSRF protection when used
   in a browser.
3. **Mutation authorization:** each write still carries an exact
   domain-separated DID-signed intent with action, role, resource and scope,
   expected state/version, nonce, and expiry. Check the appropriate DID
   relationship and current registry grant, then enforce contract quorum for
   maintainer actions. A login session does not replace the signed intent or
   let the server sign for a remote actor. Reject stale, cross-role,
   wrong-scope, replayed, and revoked actions before journal persistence.
4. **Eligibility:** policy may require a challenge-bound Midnight VP/VC.
   Verify its signature, issuer authority, expiry, and live VC-owned status
   off-ledger; persist only a redacted commitment and receipt. The credential
   proves a policy predicate, not possession of the actor's DID key. The
   registry does not own wallet keys, VC status, holder claims, or presentation
   activity.

The first issuer journey should use a test organization-eligibility assertion
or another non-personal fixture with a clearly named policy. Passport,
national ID, driver's license, and organization screening are **not** default
login requirements. A later policy may opt into a reviewed predicate with
data minimization and a separate issuer/status trust decision. Midnight
Passport is not a Ledger 8 dependency for this milestone.

## Client and CLI contract

Provide one typed client for challenge acquisition, DID-signed request
submission, pending-state polling, maintainer review/vote, and independent
decision evidence verification. Keep public reads separate from authenticated
writes. The CLI should consume this client instead of reaching into a fixture
workspace for the acceptance journey. No CLI command should infer finality
from HTTP `202`, an indexer claim, or the submitting provider alone.

On each response, distinguish `accepted-for-processing`, `finalized`,
`rejected`, and `unknown-after-timeout`. A timeout on a write must be reconciled
by exact request identity; it must not blindly resubmit with a fresh nonce.
Expose stable problem codes for unauthorized identity, wrong role/scope,
expired or consumed challenge, stale state, unavailable DID/status/finality,
and ambiguous submission. Do not leak raw VC/VP or private operator data in
errors or logs.

## Acceptance matrix

| Journey | Positive evidence | Required negative evidence |
| --- | --- | --- |
| Applicant sign-in | Fresh DID challenge establishes the intended actor | Missing, reused, expired, wrong-origin, wrong-deployment, wrong-key-relationship, and deactivated DID |
| Issuer application | Exact role/scope request and eligible VP produce a redacted receipt | Foreign DID, wrong scope, invalid VP, untrusted issuer, revoked or unavailable status, replay |
| Maintainer vote | Distinct authorized actors vote on the exact proposal and finalize the transition | Self-approval, duplicate key, wrong proposal, stale sequence, insufficient quorum, suspended maintainer |
| Verifier and auditor | Each role applies for its own exact grant and gets an independent decision | Issuer grant cannot authorize verifier/auditor action; audit grant does not confer data access |
| Relying-party read | Independent client verifies finalized epoch, current grant, DID key and scope | Tampered bundle, wrong genesis/contract, stale epoch, revoked grant, unsupported historical claim |
| Recovery and offline | Actor journey survives restart; ambiguous write reconciles; runtime egress denied | No duplicate transition after lost response; external HTTP/DNS/WebSocket attempts fail |

Run API/CLI contract tests with injectable authenticators first, but label
them as unit/integration evidence. The exit gate requires the same cases
against a reviewed, source-pinned local ledger and independently authenticated
finality, including real VC-owned status. Preserve the source revision,
install inventory, genesis, contract address, actor identities, finalized
checkpoint, and test result in one private candidate record. Existing
`test:e2e:demo` and Playwright fixture runs remain a separate fast lane.

## Delivery order

1. Specify and test the off-chain DID request-authentication adapter, challenge
   store, session boundary, and fail-closed API integration. Bind the exact
   long-form state to a versioned challenge transcript, authenticate only a
   verification method in the document's `authentication` relationship, and
   keep its algorithm distinct from the ledger/Jubjub mutation-signature
   format. Reuse DID resolution and signing libraries; do not implement DID
   CRUD here. Keep on-chain resolution behind an explicit later mode.
2. Add the typed API client and CLI commands, with protocol-level positive
   and negative tests. Reuse the existing signed-intent verifier.
3. Supply the approved host ports, live VC status adapter, and independent
   finalized reader for one local Ledger 8 deployment.
4. Run issuer, verifier, auditor, maintainer, and relying-party scenarios;
   publish redacted evidence and a fresh-checkout adoption guide. Keep manual
   security and operator approval explicit.

The first local code increment exports a domain-separated actor-authentication
challenge transcript and a host-facing issue/verify service. It requires a
host-provided, atomic one-use challenge store and an independently authenticated
current DID resolver. A local file adapter now provides cross-process atomic
consumption, bounded issuance, and restart-safe consumed tombstones. An opt-in
HTTP adapter now exposes challenge verification and 15-minute process-local
bearer sessions. When configured alongside private VP intake, it requires an
applicant-purpose session matching the host-authenticated DID; the pending
subject and VP policy remain separate checks. The packaged CLI does not wire
this adapter. Both browser apps offer opt-in DID sign-in in Workspace settings
through a shared browser-only client and an external signer on a same-origin
host. Applicant and maintainer sessions have distinct purposes; neither grants
a registry role, VP eligibility, or governance authority. The fast headless
journey tests that client against a real loopback HTTP host. Playwright covers
both mocked source-state UI and same-origin browser journeys using the real
loopback challenge/session API with external test signers: a fixture DID
resolver for the ledger-backed path and a self-certifying long-form DID for
the off-chain path. The applicant-only private request list is optional host admission
metadata, not a ledger decision or VP eligibility proof. There is no qualified
production resolver, live VC-owned status adapter, or deployed actor journey.
The local challenge schema, verifier, and browser client now distinguish a
self-certifying long-form off-chain DID with an Ed25519 authentication key from
the ledger-backed Jubjub path. Focused API and browser-client tests plus
`pnpm run demo:did-auth:smoke` exercise both sign-in paths through a real
loopback HTTP host, including a path-based authentication method and explicit
no-role/no-other-applicant-data checks. The packaged API CLI now has an
explicit loopback workspace-only off-chain sign-in option with a private
durable challenge store, synthetic workspace-instance binding, and an
optional same-origin built-portal asset root. A
process-level headless journey checks origin denial, one-use replay after
restart, and session revocation on restart. The packaged-host journey also
uses the shared typed client to sign in and sign out, independently derives
the synthetic workspace binding, and rejects a mismatched binding before
signing. Playwright also exercises off-chain sign-in and sign-out in both
actual CLI-served portals while blocking external browser egress and checking
that no governed write is sent. The packaged headless journey denies
unauthenticated and maintainer-purpose private-list reads; an applicant
session sees an explicit unavailable result until a registration adapter is
configured. This is fixture authentication,
not a reviewed local-ledger host configuration or deployed actor
authorization. The VC method-binding helper still rejects off-chain DIDs and
must remain separate from sign-in. Off-chain long-form state is immutable and
has no live deactivation signal, so short session lifetime and explicit mode
labeling matter. The signed local-ledger CLI remains read-only and cannot
claim deployed actor authentication or authorization.

The fast headless gate also runs the qualified VP application-intake fixtures
for issuer, verifier, auditor, and maintainer after building the prebuilt
runtime. Those tests bind the presentation to pinned deployment and policy
context, check one-use challenge consumption, and deny mismatched contexts.
The auditor case also crosses a real loopback HTTP host, deriving its expected
audience from the listening origin and its policy from the registered application.
That case signs into a phase-0 DID applicant session before private VP intake;
an applicant header alone and a signed-out session are denied. Sign-in returns
no role or VP-eligibility claim. The separately verified presentation remains
necessary before redacted evidence is accepted, and governance is still separate.
These cases run against local adapters and a Compact simulator, not a deployed
VC/status authority or a finalized ledger host.
The signed issuer, verifier, auditor, and maintainer CLI journeys also obtain a
phase-0 applicant DID session from a one-use challenge before private
registration and VP intake. A missing session is denied, and sign-in returns
neither a role nor VP eligibility. Each loopback host separately denies a wrong
VP audience and changed application-policy version before accepting the valid
presentation. Maintainer quorum signatures remain a distinct governed action;
these fixture and simulator journeys do not establish deployed actor authority.

The API health response now reports private application registration and list
ports independently. The applicant portal explains and disables preparation
and registration controls when registration is explicitly not configured, and
omits its "My applications" route only when the host explicitly
reports that the list port is absent; older hosts without these hints retain
the existing paths. These are navigation hints, not authorization checks:
private endpoints still require their own signed-intent or applicant-session
checks and may return unavailable even when a port is configured.
The packaged-host process smoke asserts both capabilities are absent, and that
neither an applicant DID session nor a maintainer-purpose session enables
registration or governance writes without their separate host ports. This is
fixture denial evidence, not a deployed authorization or finality result.
The shared typed client now distinguishes an unconfigured private applicant
list from an available empty list, validates entries, and rejects other HTTP
errors or the wrong session purpose. The packaged CLI smoke uses this client
against the real loopback host; it does not substitute for a qualified
registration port or finalized decision polling.

The next local client/CLI increment moves the pending-registration response
schema into the domain package and exposes a session-bound typed registration
call. It checks the signed applicant DID, key, registry, intent expiry, exact
same origin, and returned pending binding; the server still verifies the
signature. The `api-register` and `api-applications` CLI commands take an
ephemeral session on stdin with its verified sign-in origin, require it to
match the selected API origin,
and never place the bearer in arguments or output. A current-time packaged
loopback host confirms the list command distinguishes an unconfigured list
from denied reuse after sign-out. A separate current-time loopback host now
exercises the executable registration command with a real DID signature and
in-memory registration port, then checks readback, actor/origin denial, and
replay. The four role simulator journeys use the shared registration call
with their fixed fixture clock. None of these runs uses a deployed local-ledger
actor host. #297 remains open for complete actor review/vote, ambiguous-write
reconciliation, and independently verified decision reads; #219/#59 remain
the deployed acceptance gate. The local branch's 97 Playwright cases cover
browser behavior and role/source-state UI, not deployed finality.

Non-critical-path follow-ups include public-network bootstrap (#200),
historical TRQP (#39), Helm (#218), npm publishing (#271), mobile acceptance
(#265), and docs-site family styling (#293).
