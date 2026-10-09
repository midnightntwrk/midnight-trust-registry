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
source returns historical evidence only when the selected epoch is present
and matches the stored bundle's epoch commitment. A snapshot with only a later
bundle cannot prove an earlier epoch, so that request returns not found rather
than a positive unanchored answer. Retaining and exporting every historical
bundle is follow-on work under [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39).
