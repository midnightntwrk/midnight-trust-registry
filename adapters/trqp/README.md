# Trust Registry TRQP Adapter

Read-only TRQP-style adapter helpers for `midnight-trust-registry`.

Current scope:

- TRQP authorization request/response schemas
- TRQP recognition request/response schemas
- explicit TR-only extensions for registry metadata and evidence-bundle export
- adapter logic over an abstract read source so the package is not tied to the
  local simulator

When `context.time` is supplied, authorization and recognition decisions use
the record's lifecycle at that time, not its current status. The API-backed
source requires a bundle for that record whose epoch commitment is in the
snapshot and whose validity window contains the requested time. A snapshot
with only a later bundle cannot prove an earlier decision; the adapter returns
`epoch-evidence-unavailable` (424), distinct from a missing statement
(404). Without `context.time`, the same epoch gate applies at the source
snapshot's generation time. `time_evaluated` reports that source evaluation
time, not the adapter's wall clock, and does not claim the snapshot is fresh
today.
Retaining and exporting every historical bundle is follow-on work under
[#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39).
