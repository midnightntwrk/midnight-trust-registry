# Standalone governed actor path for 0.1.0

This is the implementation and acceptance boundary for issue #219. The first
release candidate is a self-hosted local-ledger runtime; Preview, Preprod,
Mainnet, historical API routes, and Kubernetes are outside this gate. A
simulator or mocked provider cannot supply deployment evidence.

## Current executable boundary

`trust-registry-api serve --local-ledger-plan` verifies a signed runtime plan,
loads a pinned current-state source, and configures finalized proposal reads.
It does **not** configure applicant/VP intake, an accepted-application
admission port, governed proposal ports, a submitting provider, or a governed
membership-action adapter. Governed proposal writes therefore return 503;
the health response establishes current-read availability, not write
readiness. The standalone current-query observer is intentionally read-only.

The integration package has a `submitLocalIssuerProposalCall` path with
Compact preflight, provider-identity comparison, and a one-attempt durable
journal, plus a pinned local submission-provider prototype. Its existing
tests use injected readers/providers. None of these is wired to the signed
production API plan, and they do not prove a deployed actor journey.
`GET /health` lists configured proposal-port roles; port presence is a
configuration observation, not an authenticated write or release verdict.

## Implementation order

1. **Bind the writer to the approved installation.** Extend the signed local
   API plan with an exact provider-module digest, immutable installed root,
   deployment/chain identity, and private journal location. Load only that
   source-matched provider code, verify it before startup and each submission,
   and keep wallet secrets outside the plan, logs, and HTTP responses. Refuse
   writes if the provider identity, finalized reader, signed plan, or runtime
   image disagree. Reuse the existing root-owned provider verification path;
   a writable development checkout is not an approved writer.
2. **Bind admission to current evidence.** Configure pending-application and
   accepted-evidence persistence for the same signed deployment. Verify the
   actual local DID resolver, VC status authority, challenge, applicant
   signature, policy, and trusted time. An accepted VP receipt alone is not a
   ledger proposal or authorization. Keep the VC-owned status adapter outside
   this repository and fail closed while it is unavailable.
3. **Specify exact issuer proposal terms.** The accepted application envelope
   supplies subject, role, scope, governed resource, and evidence commitment.
   It does not supply the Compact proposal's trust level or complete status
   policy binding. Add a canonical, reviewer-visible issuer proposal intent
   that supplies those terms and binds them to the accepted application,
   current policy, and local deployment. Do not invent a default trust level
   or status registry. The maintainer and evidence-verifier signatures must
   cover the resulting exact Compact payload and action sequence.
4. **Wire one production issuer path.** Supply the API's issuer proposal port
   with a side-effect-free preflight, current finalized reader, one-attempt
   journal, approved provider, and finalized resolution. Prepare and submit
   must reject stale plan, scope, evidence key, signer set, nonce/sequence, or
   provider identity before broadcast. Ambiguous submission remains reserved
   under #220; no blind retry or automatic journal release.
5. **Expand actor coverage.** Add verifier, auditor, maintainer, recognition,
   and governed decision adapters using the same deployment, provider, and
   recovery invariants. A partial issuer path must not be reported as the
   full actor journey. After each finalized mutation, require a manually
   reviewed and re-signed current API plan and controlled restart.

## Acceptance on a real dedicated local ledger

- The operator installs an exact-source pinned bundle, independently reviews
  and signs genesis and the maintenance roster, deploys once, and verifies
  finalized constructor, authority, and verifier-key readback. No test may
  substitute a simulator address, node-reported genesis alone, or fixture
  finality for these steps.
- With external egress denied, a funded local actor submits a genuine issuer
  application and live DID/VC/status evidence; the accepted proposal and
  governed decision appear at authenticated finalized checkpoints and in
  current API/TRQP reads. Repeat for the remaining actor roles and recognition.
- Negative runs reject a wrong provider/deployment, stale signed plan, wrong
  policy/status authority, substituted evidence, duplicate signer, invalid
  sequence, unavailable finality, and unresolved journal reservation without
  an unintended transaction.
- Restart and distinct-project restore retain deployment, journal, and current
  state; an ambiguous write is reconciled only under independently reviewed
  evidence. Host, wallet, browser, API, proof-server, and container egress
  denial each have positive-control logs.
- Preserve raw receipts, checkpoints, plan and image digests, commands,
  timestamps, and redacted reviewer decisions under the private acceptance
  inventory. A non-author human records a security verdict under #232.

Until these checks run against one reviewed candidate, issue #219 stays open,
`releaseQualified` stays false, and draft promotion #198 stays draft.

The first code increment for step 3 is `bindAcceptedLocalIssuerProposalTerms`.
It checks one captured pending/accepted application pair, exact submitted
evidence, the approved local network/genesis/contract, and a canonical trust
level and status-policy binding. It also rejects an application whose policy
ID, version, or registry differs from the caller's authenticated current-ledger
selection. The caller must supply that selection; the binder does not
authenticate finality. It emits a review digest and status-policy
commitment only. The digest covers the exact accepted evidence submission,
including its signature and receipt, plus the pending application record,
rather than only the envelope commitment.
It does not verify the live VC status authority, current
ledger policy, maintainer signatures, provider identity, or finality; the
production API does not yet call it. Those checks remain mandatory before
any broadcast or E2E verdict.

The issuer proposal HTTP prepare/submit requests can now carry the same
canonical terms, and local-ledger mode refuses either request without them.
The port receives the terms for repeated binding at prepare, preflight, and
execute time. This is request plumbing, not an installed write adapter: the
signed local API CLI still configures no issuer proposal port.
The binder now derives the unsigned Compact issuer fields from the accepted
envelope and exact terms. It intentionally cannot fill the active policy
commitment, registered evidence-verifier key, signatures, or authenticated
finalized action sequence; a real writer must obtain and recheck those from
the current ledger before it signs or broadcasts.
`prepareUnsignedLocalIssuerProposalCall` now supplies that signature-free
Compact context from a caller-authenticated finalized ledger, checking the
active policy and evidence-verifier key, scope availability, and action
sequence. The existing signed call reuses the same preflight. This helper
does not authenticate the ledger source or configure the production API.
`prepareBoundLocalIssuerProposal` joins the accepted application and terms to
that preflight only when the selected policy snapshot commitment equals the
current Compact ledger commitment. It returns a separate signing-review digest
covering the active policy, verifier key, action payload, sequence, and
threshold. The caller must still authenticate finality, time, and live VC
status before asking anyone to sign.
The issuer SDK handoff now separates side-effect-free submission preflight
from execution after an externally owned journal reservation. The original
standalone helper still owns its own journal, but a future API port must use
the after-reservation form because the HTTP server already reserves before
calling `execute`. Both forms recheck the finalized ledger and provider
identity; neither by itself proves that the provider code is pinned or that
SDK finalization is independently authenticated.
An opt-in `createBoundLocalIssuerProposalPort` now composes the accepted
application binder, current policy/ledger preflight, live-evidence callback,
provider-code check, SDK preflight, and after-reservation execution. Its
dependencies are deliberately mandatory and deployment-owned; the signed
local API CLI does not instantiate it. Its injected-dependency tests prove
fail-closed ordering, not a deployed issuer journey. A production host still
needs an independently authenticated finality reader, VC-owned live status
adapter, approved immutable provider loader, signed write-plan pins,
finalized proposal resolution, and a full offline actor run. If state changes
after HTTP preflight but before the reserved execution, the journal retains
the reservation for explicit reconciliation rather than silently retrying.
The port now separately requires a deployment-trusted time source and rejects
accepted application evidence before its verified-at time or at/after expiry
on every prepare, preflight, and execute. The same sampled time is passed to
the live evidence callback; this explicit guard does not authenticate that
callback or make the host clock a trusted source. Execution samples trusted
time again after the SDK preflight, immediately before broadcast. Finalized
inclusion may still occur later; the host needs an approved, independently
authenticated transition-time policy before claiming `A01`.
The private file admission store now captures pending and accepted records
from one validated persisted-state read. HTTP admission prefers that captured
pair when the port supports it, and the issuer-port assembly requires it;
legacy two-method adapters remain compatible but must not be mistaken for an
atomic production admission source.
The approved local read source also exposes the selected policy snapshot,
Compact ledger, and finalized block hash from one bounded read, then adds
the reviewer-signed genesis pin at the plan wrapper. This avoids mixing two
checkpoints while preparing issuer signatures. It remains a pinned local-node
observation, not independently authenticated finality or a wired CLI writer.
