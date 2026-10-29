# Local 0.1.0 independent security-review handoff

This is a **review preparation checklist**, not a finding disposition, human
signature, or release approval. It supports [issue #232](https://github.com/midnightntwrk/midnight-trust-registry/issues/232)
for the self-hosted local/offline candidate only. Public-network qualification
is deferred; optional Helm is not a local RC gate. Keep #198 draft.

## Identify one candidate

The release owner supplies the reviewer with the exact merged source commit,
its verified GPG signer and DCO trailer, the install-inventory SHA-256, the
release-manifest SHA-256, image and proof-parameter digests, the selected
`standalone` network profile, and the private setup identifier. Do not review
an old bundle against a newer source commit. The reviewer independently checks
the commit and bundle bytes, rather than trusting a node-reported hash or a
wizard status label. Record the source SHA and inventory digest in the verdict.

The wizard checks retained genesis, roster, and deployment-bound committee
approval document/signature digests and setup bindings before the associated
deployment or transition action, and reports
`invalid-approval-evidence-investigate` on a mismatch. This detects local
evidence corruption; it does **not** reverify GPG against an independently
pinned reviewer key on each status read or establish that the reviewer approved
the actual chain specification. The reviewer must inspect the original exact
signed bytes and external trust anchor. Preserve mismatched evidence rather
than repairing a record in place.

```sh
git verify-commit "$SOURCE_SHA"
git show -s --format='%H%n%B' "$SOURCE_SHA"
node scripts/check-standalone-install.mjs "$INSTALL" "$SOURCE_SHA"
shasum -a 256 "$INSTALL/install-inventory.json"
node scripts/check-standalone-journey-prerequisites.mjs "$SETUP" "$SOURCE_SHA"
```

The last command exits nonzero when prerequisites are missing. Its report
describes wizard-recorded state only, **not** independent finality, actor
success, or release qualification. Do not run a destructive light build in
the artifact-bearing checkout; use a disposable checkout for that CI lane.

## Review the trust boundaries

| Boundary | Inspect | Required independent evidence |
| --- | --- | --- |
| Source and install | Signed source, manifest-backed package tarballs, six pinned images, proof parameters, provider code identity | Exact-source inventory and digests authenticated outside the bundle; no mutable image or package substitution |
| Genesis and network | Profile selection, real chain specification, proposed pin, exact-byte reviewer GPG verification | A human-reviewed chain-spec digest and detached signature on the exact wizard approval bytes; the node's candidate and demo references are not approval |
| Deployment and finality | One-attempt journal, provider import and dependency confinement, constructor and verifier-key readback | Authenticated finalized transaction inclusion, contract address, constructor state, every expected key hash, and readback at the same selected chain |
| Maintenance | Approved threshold, distinct public keys and custody, bootstrap transition, ambiguous-submission quarantine | Signed release roster, deployment-bound approval, finalized transition/counter readback, and rejection of old bootstrap authority; 1-of-3 development smoke is insufficient |
| API and actor writes | Signed current-only API plan, selected deployment/state, live DID/VC/status authority, issuer writer and mutation journals | Real local-ledger actor receipts and current reads for the documented `A01`-`A04` cases, including negative authorization paths; a read-only CLI or fixture port does not pass |
| Isolation and recovery | Container/host/wallet/browser/proof-server egress, API restart, separate-project ledger restore | Positive controls plus denied egress, continuity against the same deployed contract, and restored finalized history from a distinct pinned ledger |

Use the [operator acceptance cases](../guide/standalone-local-journey.md)
`L01`-`S01` and the [acceptance map](milestone-0.1.0-acceptance-map.md)
to inspect each raw receipt. Simulator, injected-provider, packed-consumer,
Playwright, and pre-deployment bridge tests are regression evidence only.
They cannot establish a deployed transaction, authenticated finality, offline
actor behavior, or recovery. The VC-owned live status adapter remains a
separate dependency; do not substitute fixture responses.

## Review the code and unresolved findings

Inspect the exact-head changes in [#238](https://github.com/midnightntwrk/midnight-trust-registry/pull/238),
[#239](https://github.com/midnightntwrk/midnight-trust-registry/pull/239), and
[#240](https://github.com/midnightntwrk/midnight-trust-registry/pull/240),
then the merged candidate commit. The [security-script type inventory](standalone-security-script-typecheck.md)
identifies remaining dynamic boundaries; passing checked-JS is not a security
verdict. Review the [scan disposition](../guide/security-scan-disposition.md)
and live required checks at each exact head. An unresolved red required scan,
high/critical finding, unsigned or stale approval, missing finalized readback,
or missing actor/recovery evidence is a **stop condition**, not an advisory.

The reviewer should record identity and independence, exact commit and bundle
digests, reviewed scope, each finding with severity and reproduction, any
linked low-severity deferral and risk owner, and an attributable signed verdict.
Critical/high fixes require re-review at the new exact head. Do not put private
keys, wallet seeds, credentials, or private setup files into a PR or issue.
The release owner records the verdict on #232; an AI-authored summary cannot
close that human gate.
