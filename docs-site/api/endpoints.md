# Endpoint reference

The exact request/response parsers live in [`packages/trust-registry-api/src/schemas.ts`](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/packages/trust-registry-api/src/schemas.ts), with route dispatch in [`server.ts`](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/packages/trust-registry-api/src/server.ts). The [OpenAPI file](/openapi.yaml) describes the public shape; Zod schemas and the server remain authoritative where a trusted port adds constraints.

## Read/query

| Method and path | Purpose |
| --- | --- |
| `GET /health`, `/v1/registry`, `/v1/registry/summary` | Source health and registry metadata |
| `GET /v1/epochs/current`, `/v1/epochs/{epochId}`, `/v1/epochs/resolve?at=...` | Current, named, or time-selected epoch |
| `GET /v1/authorizations/{role}` | List issuer, verifier, or auditor entries (optional status filter) |
| `GET /v1/authorizations/{role}/{id}` and `.../evidence` | Record and separately retrievable bundle |
| `POST /v1/authorizations/evaluate` | Evaluate exact DID/role/resource at a timestamp |
| `POST /v1/authorizations/resolve` | Resolve exact DID/role/resource in current view |
| `GET /v1/recognitions` and `/v1/recognitions/{id}` | Scoped external recognition list/record |
| `GET /v1/recognitions/{id}/evidence` | Recognition evidence bundle |
| `POST /v1/recognitions/evaluate`, `/resolve` | Historical/current exact-scope recognition query |
| `GET /v1/trqp/metadata/{authorityId}` | TRQP metadata projection |
| `POST /v1/trqp/{authorizations,recognitions}/{query,evidence}` | TRQP query/evidence projection |

Issuer lookup requires `tr:issuer-resource:v1:<sha256>`. Verifier and auditor lookups require `tr:request-resource:v1:<sha256>`. A bare request-profile ID is not accepted. `at` is an ISO timestamp with offset; the service clock is not a consensus clock.

## Private intake and governed writes

| Method and path | Availability |
| --- | --- |
| `POST /v1/pending-applications` | Signed pending registration via injected trusted port |
| `POST /v1/application-evidence/{id}/challenges`, `/submissions` | Authenticated, one-use VP challenge/intake via `applicationVp` port |
| `GET /v1/application-evidence/{id}/binding`, `/receipt` | Applicant-authorized binding and accepted redacted receipt |
| `POST /v1/recognition-evidence/{id}/challenges`, `/submissions` | Private accreditation and authority assertion intake |
| `GET /v1/recognition-evidence/{id}/accepted` | Authorized accepted recognition receipt |
| `POST /v1/governed/{role}/{id}/proposal/prepare`, `/submit`, `/resolve` | Compact-backed role proposal, external signatures, read-only recovery; role-specific port required |
| `GET`, `POST /v1/governed/{role}/{id}/actions/{action}` | Prepare then submit externally signed approve/activate actions |
| `POST /v1/governed/policy/{thresholds,evidence-verifier}/{prepare,submit}` | Two distinct policy/key actions, each with fresh context |
| `POST /v1/governed/epochs/prepare`, `/publish` | Governed epoch signing/publication port |
| `GET /v1/registry/mutation-context`, `POST /v1/mutations` | Workspace revision and DID-signed intent; resolver required for writes |

The `governed` proposal roles are `issuer`, `verifier`, `auditor`, `maintainer`, and `recognition`; recognition has a receipt-gated prepare/submit route. The action route supports approve/activate only under the injected governed port. Any absent port yields `503` rather than a workspace mutation. Proposals bind the evidence-verifier key and policy; action signatures bind the current sequence and predecessor event.

## Unsafe demo only

`POST /v1/applications`, `POST /v1/applications/{target}/{id}/{action}`, and `POST /v1/epochs/publish` are legacy workspace replay routes. They are disabled by default; `--unsafe-demo-mutations` enables them only on a loopback listener with a mutable workspace. They bypass actor authorization and must not be exposed as production governance.
