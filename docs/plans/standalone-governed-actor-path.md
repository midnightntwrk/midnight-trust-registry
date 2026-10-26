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
journal. Its existing tests use injected readers/providers. It is not wired
to the signed production API plan and does not prove a deployed actor journey.

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
