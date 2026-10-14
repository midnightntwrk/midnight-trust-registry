# HTTP API: trust boundaries

The HTTP service is a **local reference gateway** over a saved snapshot or mutable operator workspace. It provides read/query routes and optional private/governed ports. Its URL is not itself a trust anchor. The [OpenAPI 3.1 document](/openapi.yaml) inventories the current routes; [endpoint groups](./endpoints.md) explain the important safety distinctions.

## Three operating modes

| Mode | How it is supplied | What it can do |
| --- | --- | --- |
| Snapshot/workspace read | Packaged CLI | Registry, epoch, authorization, recognition, TRQP queries |
| Trusted embedded host | Inject DID resolver and role-specific ports | Signed mutation, private VP intake, Compact-governed proposals/actions |
| Unsafe loopback demo | CLI `--unsafe-demo-mutations` with workspace | Unsigned workspace replay for UI smoke only |

Without a trusted port, a governed or private route returns `503`; it does not silently fall back to unsigned workspace replay. The packaged CLI does not configure a production DID resolver or Compact submitter. `202` means a local port accepted a transition; it does **not** attest to network finality.

## Authentication is not enough

Private application routes call a trusted `authorizeRequest` callback before reading a body. The embedding host must bind the authenticated principal to the application and defend cookie sessions against CSRF. The reference API does not grant wildcard browser CORS access to raw VPs. Signed `/v1/mutations` verifies a DID method relationship, exact workspace revision, operation, nonce, and five-minute validity window; the packaged CLI returns `503` for writes without an injected resolver.

## Error model

Errors use problem details with `type`, `title`, `status`, and optional `detail`/`instance`. Important distinctions include malformed input (`400`), invalid signature (`401`), unauthorized actor or signer (`403`), missing record (`404`), replay/stale state/lock conflict (`409`), absent historical evidence (`424`), and missing trusted port (`503`). Do not retry a `not-observed` proposal blindly: ledger observation and private admission are not one atomic transaction.

## Independent verification

Read responses may include evidence, but the caller must pin the registry authority and an accepted finalized epoch independently. A positive status without that verification is informational only. See [evidence and time](../model/evidence.md).
