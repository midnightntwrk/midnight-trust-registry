# Trust Registry TRQP Adapter

Read-only TRQP-style adapter helpers for `midnight-trust-registry`.

Current scope:

- TRQP authorization request/response schemas
- TRQP recognition request/response schemas
- explicit TR-only extensions for registry metadata and evidence-bundle export
- adapter logic over an abstract read source so the package is not tied to the
  local simulator
- `verifyTrqpAuthorizationEvidenceResponse` and
  `verifyTrqpRecognitionEvidenceResponse` for independently anchored proof and
  decision checks against an exact request
- `verifyTrqpAuthorizationEvidenceFromApi` and
  `verifyTrqpRecognitionEvidenceFromApi` to fetch the local/HTTPS evidence route
  and apply those checks without treating 404/424 as a deny decision

When `context.time` is supplied, authorization and recognition decisions use
the record's lifecycle at that time, not its current status. Otherwise the
adapter samples its off-ledger clock once. `time_evaluated` reports that
instant, never `snapshot.generatedAt`. A plain query is a source-snapshot
projection, not cryptographic proof. The evidence endpoint additionally
requires a bundle for the selected record whose epoch commitment is accepted
in the snapshot and whose validity window contains the selected instant. A
snapshot with only an older bundle can answer a current query but cannot
prove it; the evidence endpoint returns `epoch-evidence-unavailable` (424),
distinct from a missing statement (404). Neither answer proves the snapshot
is fresh relative to a later ledger state. See
[`docs/spec/trqp-time-and-evidence.md`](../../docs/spec/trqp-time-and-evidence.md).
Before returning an evidence response, the adapter also rejects source data
whose epoch registry, policy ID/root, or lifecycle decision contradicts the
included statement at `time_evaluated`. This is a consistency check, not an
independent ledger anchor or cryptographic proof verification.
The API can export selected archived statement bundles; durable retention and
canonical network-history selection remain follow-on work under
[#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39).

The evidence verifiers require a caller-selected explicit `context.time`, a
trusted authority DID, and an epoch context obtained independently of the
TRQP response. They check the echoed tuple and time, epoch signature and
inclusion proof, exact statement scope, and the projected allow/deny result.
Recognition verification also requires `context.recognized_registry_id` and
the exact `scope_context` map; recognition never grants local issuer authority.
These helpers do not authenticate ledger finality, select the canonical
historical epoch, or validate a wall-clock source. A 404/424 response remains
an unavailable proof, not a verified deny decision.
