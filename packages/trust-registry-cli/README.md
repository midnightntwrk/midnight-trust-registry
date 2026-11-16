# Trust Registry Operator CLI

Local operator CLI for `midnight-trust-registry`.

Current scope:

- create a deterministic demo snapshot backed by the local simulator harness
- create a mutable operator workspace backed by an append-only CLI action journal
- inspect registry, policy, authorization, recognition, and epoch records from a
  saved snapshot or a saved operator workspace
- submit, approve, activate, suspend, revoke, and archive issuer, verifier,
  auditor, and recognition records without raw simulator access
- publish a registry epoch anchor from the local operator workspace
- export anchored issuer, verifier, auditor, and recognition evidence bundles as JSON
- inspect historical issuer, verifier, auditor, recognition, and epoch state at a
  specific timestamp
- render deterministic human-readable audit reports from a saved snapshot or a
  saved operator workspace
- inspect read-only Compact ledger state at an operator-pinned finalized
  network block for a deployed Trust Registry address
- submit a pre-signed pending application or list an applicant's own pending
  requests through the same-origin actor API, without fixture-workspace edits

The package also exports `publishSimulatorSnapshot(harness, fixtures, previousSnapshot?)` for
local integration scenarios. It publishes a simulator registry epoch and
projects specified governed issuer, verifier, auditor, and recognition
fixtures into the same snapshot schema consumed by the API. It is not a
production ledger indexer or a substitute for externally accepted finality;
call it explicitly after governance transitions rather than on each read.
Pass the preceding snapshot on each re-projection to retain prior evidence
bundles and epoch commitments for temporal queries.

## Actor API commands

`api-register` accepts one stdin JSON object with `{ "session": ..., "request": ... }`,
where `session` is the short-lived applicant-purpose DID session and `request`
is an externally signed pending-application intent. `api-reconcile` accepts
the same original `{ "session": ..., "request": ... }` after an unknown write
outcome and reads the private exact-application endpoint without submitting
again. `api-applications` accepts
`{ "session": ... }` and returns either an available list or an explicit
unavailable state. Both commands require `--api-base`; the session on stdin
carries the verified DID sign-in origin rather than deriving it from the API
URL being called. They reject a different origin, redirects, expired sessions, invalid
requests, and malformed responses. Pipe this JSON from a trusted local signer
or session process. Do not put bearer tokens in shell arguments, history,
files, or logs. The CLI does not create or store keys or sessions.
If the registration response is lost, unreadable, server-failed, or mismatched,
the outcome is unknown: do not resubmit the signed request. Run `api-reconcile`
with the original request and session. `observed` means the subject-scoped
record contains the canonical commitment of the exact signed request. `unknown`
means the record is missing, unavailable, unreadable, or predates commitments;
it is not permission to retry. The private list is only a summary and cannot
reconcile an exact request. The file-backed reference store can retain the
intake record across a host restart, while the in-memory store cannot. Neither
read proves a finalized ledger decision; complete deployed recovery and
independent decision verification remain tracked in #297.

Registration means **pending intake only**. It does not grant a role, accept a
VP, approve a proposal, or prove ledger finality. The older `submit` and
`approve` commands above remain explicitly fixture-workspace operations, not
equivalent actor API writes. The current headless role journeys exercise a
simulator host; deployed-ledger qualification is separate.

Build the workspace first from the repo root:

```bash
./run.sh --light
```

Example usage from the repo root:

```bash
node packages/trust-registry-cli/bin/trust-registry.mjs init-demo \
  --output ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-cli/bin/trust-registry.mjs summary \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs submit \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --label passport \
  --json

node packages/trust-registry-cli/bin/trust-registry.mjs approve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1

node packages/trust-registry-cli/bin/trust-registry.mjs activate \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1

node packages/trust-registry-cli/bin/trust-registry.mjs export-evidence \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1 \
  --output ./artifacts/trust-registry/passport-issuer-evidence.json

node packages/trust-registry-cli/bin/trust-registry.mjs inspect \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json \
  --kind issuer \
  --id auth:issuer:passport:v1 \
  --at 2026-05-20T00:30:00Z

node packages/trust-registry-cli/bin/trust-registry.mjs report \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind full
```

For read-only deployment inspection, provide the network RPC and indexer
endpoints through `TR_RPC_URL`, `TR_INDEXER_HTTP_URL`, and
`TR_INDEXER_WS_URL`. Set `TR_EXPECTED_GENESIS_HASH` to a nonzero hash approved
out of band, not one copied from the same RPC response. Then run:

```bash
node packages/trust-registry-cli/bin/trust-registry.mjs inspect-deployment \
  --network preview --address 0x<64-hex-digit-contract-address>
```

The JSON result includes the finalized block hash, registry/network/policy
commitments, and governance action sequence. It contains no wallet secret and
does not sign or submit transactions. A successful read does not prove that
the node is honest, that the deployment was authorized, or that #200's
public-network qualification is complete. Keep project-token endpoint URLs
out of shell history and logs.

The unreleased v1 operator snapshot requires a separate `auditorEntries`
collection. CLI and API role lookups never treat a verifier entry as an
auditor grant. The returned lifecycle state must be checked: archived evidence
preserves history but does not establish current authorization.
Local snapshots and workspaces created before this field was added must be
regenerated; there is no compatibility fallback for the unreleased format.
