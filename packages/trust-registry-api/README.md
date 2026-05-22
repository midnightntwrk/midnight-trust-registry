# Trust Registry API

HTTP query surface for the local Midnight trust-registry reference
implementation.

Current scope:

- serve read-only registry, epoch, authorization, recognition, and evidence
  endpoints from a saved operator snapshot or mutable operator workspace
- expose TRQP-compatible authorization and recognition routes by reusing the
  existing adapter package
- keep the first service slice file-backed and local-first instead of introducing
  a separate database or runtime persistence layer

Current route set:

- `GET /health`
- `GET /v1/registry`
- `GET /v1/registry/summary`
- `GET /v1/epochs/current`
- `GET /v1/epochs/:epochId`
- `GET /v1/authorizations/:role`
- `GET /v1/authorizations/:role/:authorizationId`
- `GET /v1/authorizations/:role/:authorizationId/evidence`
- `POST /v1/authorizations/resolve`
- `GET /v1/recognitions`
- `GET /v1/recognitions/:recognitionId`
- `GET /v1/recognitions/:recognitionId/evidence`
- `POST /v1/recognitions/resolve`
- `GET /v1/trqp/metadata/:authorityId`
- `POST /v1/trqp/authorizations/query`
- `POST /v1/trqp/authorizations/evidence`
- `POST /v1/trqp/recognitions/query`
- `POST /v1/trqp/recognitions/evidence`

Run locally against a saved workspace:

```bash
npm run build -w @midnight-ntwrk/trust-registry-api
npx trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
```

This package is intentionally read-only for the first API slice. Governed
application submission and approval endpoints remain a follow-on backlog item.
