# Standalone actor host: implementation handoff

This is the contract for an embedding host that wants to run the **real**
self-hosted 0.1.0 actor acceptance cases. It is not a recipe for turning a
fixture into release evidence. The packaged signed-plan API CLI is currently
read-only and exposes no production governed-write roles. The opt-in issuer
port has injected-dependency tests, not a deployed local-ledger run. A host
must be independently reviewed before its results can count toward `A01`.

Start with the [standalone first run](standalone.md) and
[end-to-end acceptance procedure](end-to-end-testing.md). Do not construct an
actor host before the independently reviewed genesis approval, release roster,
finalized deployment/readback, and signed current API plan exist for one exact
source and install inventory. A 1-of-3 development roster, node-reported
genesis candidate, or simulator receipt is not an approval.

## What the host must supply

`createBoundLocalIssuerProposalPort` accepts deployment-owned dependencies;
the repository does not supply a production implementation of them.

| Dependency | Required behavior and evidence |
| --- | --- |
| Captured admission | Read pending application and accepted evidence from one persisted state revision. Bind the challenge, applicant DID, role, target, and submitted evidence before preparing signatures. |
| Authenticated finalized snapshot | Independently authenticate finality, genesis, contract address, policy snapshot, verifier-key catalog, maintenance authority, and governance sequence. Do not treat the SDK submitting provider or an indexer response alone as independent finality. |
| Trusted time | Return a deployment-approved time sample at every prepare, preflight, and execution. The API host clock is not automatically trusted. |
| Live evidence verifier | Resolve DID, VP, VC status authority, and challenge using local services and the governed issuer status-policy binding. Reject revoked, stale, wrong-authority, mismatched-registry, or unavailable status. The VC-owned live status adapter is not yet published; a fixture callback is insufficient. |
| Installed provider | Verify immutable, root-owned provider bytes and their dependencies against the independently reviewed source, install inventory, and detached-signed writer annex before every SDK use. |
| Submission journal | Initialize the API-owned, deployment-bound one-attempt journal at the approved path. Preserve ambiguous reservations across process restarts; never blindly resubmit. |

The live evidence callback must return a versioned
`tr-live-issuer-evidence-verification-v1` result. The issuer port rejects an
absent result or one whose source, network, contract, finalized block,
application, evidence commitment, governed status-policy commitment, status
registry, status-authority method, or trusted time differs from the inputs it
checked. This guards against accidental cross-candidate reuse and no-op
callbacks. **The returned fields are still the host adapter's assertions**;
they do not cryptographically prove DID, VC, status, or finality verification.
The adapter's actual verification rules, trust anchors, endpoint allowlist,
and failure behavior require separate implementation and review.

## Run the acceptance case

1. Verify the exact signed API plan and detached issuer-writer approval against
   the installed provider tree. Start the host only after those checks pass;
   do not load an arbitrary module from a writable checkout.
2. Confirm `/health` identifies the signed plan and the configured issuer
   proposal role. A health response is capability preflight, not `A01` success.
3. While external egress is denied, submit a real issuer application with
   local DID/VC/status evidence. Capture the accepted evidence, exact-intent
   signatures, journal reservation, transaction, authenticated finalized
   event, and current by-ID/API readback from the same deployment.
4. Recheck the live evidence and deployment immediately before broadcast.
   If status, trusted time, governance sequence, provider bytes, or signing
   context changed, stop. Keep an ambiguous reservation for independently
   reviewed reconciliation rather than retrying it.
5. After a finalized mutation, manually review and re-sign the current API
   plan, restart the API, and verify the new current read. Do not use a stale
   plan or mix receipts from another source, install, genesis, or contract.

Record negative cases for missing live verifier output, a substituted status
registry or authority, revoked/unavailable status, stale finalized block,
expired evidence, changed provider content, wrong signer, and ambiguous
submission. Each denial must show that no unintended ledger mutation occurred
or that the submission remains quarantined. The
[operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record)
defines the complete `L01`-`S01` evidence set. Issuer-only `A01` does not
complete verifier, auditor, maintainer, recognition, relying-party, offline
egress, restore, or independent human security review cases.

Keep raw redacted receipts and reviewer decisions in one private acceptance
bundle. The inventory checker records hashes and verdicts but does not
authenticate their truth. Until the VC-owned adapter, authenticated finality,
deployed actor run, and human review exist, leave the case `not-run` and the
0.1.0 promotion draft unmerged.
