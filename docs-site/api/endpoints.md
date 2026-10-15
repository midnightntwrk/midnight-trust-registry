# Endpoint reference

The exact request/response parsers live in [`packages/trust-registry-api/src/schemas.ts`](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/packages/trust-registry-api/src/schemas.ts), with route dispatch in [`server.ts`](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/packages/trust-registry-api/src/server.ts). The [OpenAPI file](/openapi.yaml) describes the public shape; Zod schemas and the server remain authoritative where a trusted port adds constraints.

## Read/query

| Method and path | Purpose |
| --- | --- |
| `GET /health`, `/v1/registry`, `/v1/registry/summary` | Source health and registry metadata |
| `GET /v1/epochs/current`, `/v1/epochs/{epochId}`, `/v1/epochs/resolve?at=...` | Current, named, or time-selected epoch |
| `GET /v1/authorizations/{role}` | List issuer, verifier, or auditor entries (optional status filter) |
| `GET /v1/authorizations/{role}/{id}` and `.../evidence` | Record and separately retrievable bundle |
| `GET /v1/decision-evidence/{role}/{id}` | Optional issuer/verifier claim for independent VC-consumer verification |
| `POST /v1/authorizations/evaluate` | Evaluate exact DID/role/resource at a timestamp |
| `POST /v1/authorizations/resolve` | Resolve exact DID/role/resource in current view |
| `GET /v1/recognitions` and `/v1/recognitions/{id}` | Scoped external recognition list/record |
| `GET /v1/recognitions/{id}/evidence` | Recognition evidence bundle |
| `POST /v1/recognitions/evaluate`, `/resolve` | Historical/current exact-scope recognition query |
| `GET /v1/trqp/metadata/{authorityId}` | TRQP metadata projection |
| `POST /v1/trqp/{authorizations,recognitions}/{query,evidence}` | TRQP query/evidence projection |

Issuer lookup requires `tr:issuer-resource:v1:<sha256>`. Verifier and auditor lookups require `tr:request-resource:v1:<sha256>`. A bare request-profile ID is not accepted. `at` is an ISO timestamp with offset; the service clock is not a consensus clock.

Decision evidence is available only when the host injects a source; otherwise it returns `503`. A successful response has `verification: "client-required"` and `evidence`, with `Cache-Control: no-store`. The reference source builder checks the indexed claim against a separately supplied finalized registry/DID reader before serving, but the HTTP response is still not a root of trust. Consumers must repeat verification with their own authenticated readers before deriving a VC signer descriptor. A missing grant returns `404`; malformed, stale, or unavailable source evidence returns `503` without falling back to a mutable snapshot.

## Private intake and governed writes

| Method and path | Availability |
| --- | --- |
| `POST /v1/pending-applications` | Signed pending registration via injected trusted port |
| `POST /v1/application-evidence/{id}/challenges`, `/submissions` | Authenticated, one-use VP challenge/intake via `applicationVp` port |
| `GET /v1/application-evidence/{id}/binding`, `/receipt` | Applicant-authorized binding and accepted redacted receipt |
| `POST /v1/recognition-evidence/{id}/challenges`, `/submissions` | Private accreditation and authority assertion intake |
| `GET /v1/recognition-evidence/{id}/accepted` | Authorized accepted recognition receipt |
| `POST /v1/governed/{role}/{id}/proposal/prepare`, `/submit`, `/resolve` | Compact-backed role proposal, external signatures, read-only recovery; role-specific port required |
| `GET`, `POST /v1/governed/{role}/{id}/actions/{action}` | Prepare then submit externally signed lifecycle actions |
| `POST /v1/governed/policy/{thresholds,evidence-verifier}/{prepare,submit}` | Two distinct policy/key actions, each with fresh context |
| `POST /v1/governed/epochs/prepare`, `/publish` | Governed epoch signing/publication port |
| `GET /v1/registry/mutation-context`, `POST /v1/mutations` | Workspace revision and DID-signed intent; resolver required for writes |

The `governed` proposal roles are `issuer`, `verifier`, `auditor`, `maintainer`, and `recognition`; recognition has a receipt-gated prepare/submit route. The action route supports `approve`, `activate`, `suspend`, `revoke`, and `archive` under the injected governed port. Archiving a proposed record is a quorum-signed denial that retains its history without inventing approval or activation timestamps. Any absent port yields `503` rather than a workspace mutation. Proposals bind the evidence-verifier key and policy; action signatures bind the current sequence and predecessor event.

An archived proposal remains available through its role-specific evidence
route. This is historical evidence, not a current grant: the client rejects it
by default, and timestamped issuer or recognition evaluation returns
`trustedAtTime: false` before and after denial.

## Unsafe demo only

`POST /v1/applications`, `POST /v1/applications/{target}/{id}/{action}`, and `POST /v1/epochs/publish` are legacy workspace replay routes. They are disabled by default; `--unsafe-demo-mutations` enables them only on a loopback listener with a mutable workspace. They bypass actor authorization and must not be exposed as production governance.
