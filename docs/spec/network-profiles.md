# Trust Registry network profiles

`packages/trust-registry-integration/src/network-profiles.json` is the versioned
catalog of supported deployment environments. `validateNetworkProfiles` rejects
unknown fields, missing or duplicate profiles, and network ID aliases. The
profile ID is an operator-facing selection; `networkId` is the value passed to
Midnight.js and recorded in deployment evidence.

| Profile | Midnight network ID | Intended use | Genesis pin |
| --- | --- | --- | --- |
| `standalone` | `undeployed` | Dedicated self-hosted local chain | Independently reviewed for each installation |
| `preview` | `preview` | Public Preview network | Independently reviewed for that network and deployment |
| `preprod` | `preprod` | Public Preprod network | Independently reviewed for that network and deployment |
| `mainnet` | `mainnet` | Public Mainnet network | Independently reviewed for that network and deployment |

The profile catalog deliberately contains no genesis hash, RPC/indexer URL,
credentials, contract address, or signing key. In particular, standalone
installations do **not** share a genesis hash: each local ledger has its own
chain specification and independently approved pin. Public providers and
endpoints may also change. The operator supplies those values separately in
the deployment plan, and the existing pin, source-revision, allowlist, and
finalized-readback checks remain mandatory.

The standalone wizard selects `standalone` and writes its network ID to the
isolated Compose stack. It cannot select a public profile. Public inspection
accepts only the three public profiles; selecting one is configuration, **not**
public-network qualification. The first 0.1.0 release candidate remains
self-hosted/local-only. Preview, Preprod, and Mainnet deployments require their
own operator, reviewed genesis evidence, authenticated finality, and security
approval before any release claim.

When changing a profile, update the catalog and its validation tests together.
Do not replace the local `undeployed` network ID with a public ID or weaken
local-only guards to make a deployment appear portable. A new chain requires a
new reviewed profile and deployment procedure rather than an arbitrary
`networkId` override.
