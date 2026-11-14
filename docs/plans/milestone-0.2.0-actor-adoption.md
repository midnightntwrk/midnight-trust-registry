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

1. **Identity:** an applicant or maintainer presents a `did:midnight` DID.
   Resolve its current, non-deactivated document against an authenticated
   ledger source. DID possession alone grants no registry role.
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

1. Specify and test the DID request-authentication adapter, challenge store,
   session boundary, and fail-closed API integration. Reuse DID resolution and
   signing libraries; do not implement DID CRUD here.
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
current DID resolver. It does not expose an HTTP login route, issue a session,
grant a registry role, or provide a qualified production store or resolver.
The existing private VP routes separately require the host to return the
matching applicant DID on every request. These primitives are unit-test
evidence only until the host integration and deployed tests above pass.

Non-critical-path follow-ups include public-network bootstrap (#200),
historical TRQP (#39), Helm (#218), npm publishing (#271), mobile acceptance
(#265), and docs-site family styling (#293).
