# Trust Registry TRQP Adapter

Read-only TRQP-style adapter helpers for `midnight-trust-registry`.

Current scope:

- TRQP authorization request/response schemas
- TRQP recognition request/response schemas
- explicit TR-only extensions for registry metadata and evidence-bundle export
- adapter logic over an abstract read source so the package is not tied to the
  local simulator
