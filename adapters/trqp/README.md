# Trust Registry TRQP Adapter

Read-only TRQP-style adapter helpers for `midnight-trust-registry`.

Current scope:

- TRQP authorization request/response schemas
- TRQP recognition request/response schemas
- explicit TR-only extensions for registry metadata and evidence-bundle export
- adapter logic over an abstract read source so the package is not tied to the
  local simulator

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
Retaining and exporting every historical bundle is follow-on work under
[#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39).
