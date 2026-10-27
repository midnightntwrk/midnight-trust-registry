# Local security-scan disposition for standalone 0.1.0

The high-severity scan on draft promotion #198 examined an older milestone
head. It is not an exact-head verdict for this unpublished local stack. Before
promotion, rerun the repository's full Scan workflow on the published candidate
and review its complete SARIF output. A passing targeted command below does
not replace that CI gate or the independent human security review (#232).

## Reproduce the Checkov findings

The failing workflow used Checkov 3.2.510. From a clean checkout at the
candidate SHA, run:

```sh
uvx --from checkov==3.2.510 checkov --framework dockerfile \
  --directory deploy/runtime --compact --quiet
uvx --from checkov==3.2.510 checkov --framework secrets \
  --file charts/trust-registry-standalone/tests/fixture-values.yaml \
  --compact --quiet
```

At local commit `81b635120fa4d3e309beb653dce664c7a3b2b588`, the first command
reported 37 passed, 0 failed, 2 skipped; the second reported 0 failed,
1 skipped. The two Dockerfile skips are only `CKV_DOCKER_7`: Checkov cannot
resolve the `ARG BASE_IMAGE` value, while both image builders require an
immutable `@sha256:` base digest. Both images now contain a process-level
`HEALTHCHECK`; Compose/Helm health probes are additional, not substitutes.
The fixture-only `CKV_SECRET_6` skip covers a repeated-character public test
fingerprint, not a credential. Do not expand these skips to other files or
checks. Re-evaluate them if the image builders or fixture change.

The full tracked-source Checkov run also found `CKV_GHA_7` on the package
publish and published-smoke workflows. Their dispatch inputs previously let
an operator choose the npm registry; on the publish job that could redirect
the npm token. Both workflows now have empty dispatch inputs, use the fixed
public npm registry, and derive only a `0.1.0-rcN` version from committed
`package.json`. The publisher uses the fixed `next` tag. On this local slice,
the targeted GitHub Actions scan reported 616 passed, 0 failed. This closes
the local workflow-input finding, not the exact-head full-scan gate or the
approval required to publish packages.

At local commit `7bdca4a44bf7b40ef5261746e1303e7cc1b07deb`, a Checkov
3.2.510 run over a temporary archive of **tracked source only** reported
Dockerfile 37 passed/0 failed/2 skipped, secrets 0 failed/1 skipped,
GitHub Actions 616 passed/0 failed, and OpenAPI 5 passed/0 failed. The
temporary archive was removed after inspection. Checkov could not render the
Helm chart because its intentionally invalid default image, beneficiary,
claim, and reviewer-key placeholders do not satisfy the values schema. This
is a scan-coverage limitation, not a Helm pass or a reason to make unsafe
defaults deployable. Render and inspect Helm separately with explicit test
values when that optional deployment surface is reviewed. The tracked-source
result does not include Opengrep, Trivy, Gitleaks, Zizmor, or a published
exact-head Scan workflow run.

## Inspect the remaining scanner output

At draft #238 head `5b6d2851`, the external Opengrep OSS check reported five
`Insecure WebSocket Detected` findings: two node URL variables in
`deploy/standalone/compose.yml`, two corresponding variables in
`charts/trust-registry-standalone/templates/indexer.yaml`, and the local
runtime guide's example connection. The earlier PGP negative-test marker is
absent from this exact-head report. The internal aggregate Scan workflow and
Trivy, Gitleaks, Checkov, and Zizmor passed, but none of those results waives
the separate red Opengrep check.

| Surface | Reviewer evidence before disposition | Stop condition |
| --- | --- | --- |
| Local Compose node-to-indexer WebSockets | Inspect the rendered project and running network/port attachments. The node, indexer, and proof server join the internal bridge, and node RPC is also published on `127.0.0.1`; verify the host binding stays loopback-only, all bridge members and host-local clients are trusted, and the bridge passes a positive-control and denied-egress probe. Confirm the operator controls Docker access and no untrusted container joins the bridge. | An untrusted bridge member or host-local process can reach RPC, the port binds a non-loopback interface, or measured isolation differs from the approved topology. |
| Optional Helm node-to-indexer WebSockets | Review rendered Service and NetworkPolicy objects, namespace labels and admission controls, then test policy enforcement on the intended CNI with both allowed and denied peers. This cluster check is **not** a local Compose RC prerequisite. | The CNI ignores the policy, another workload can impersonate an allowed peer, or the rendered policy is not the observed policy. Do not claim Helm deployment qualified from template tests. |
| Runtime guide example | Confirm the example is explicitly scoped to the private local bridge and does not teach an externally reachable plaintext endpoint. | The documented address can be reached from an untrusted network or reused as a public-network default. |

Plaintext on a private bridge still exposes traffic to a compromised peer or
host administrator; NetworkPolicy is not encryption. The independent human
reviewer must record whether that residual risk is acceptable for the
self-hosted, operator-controlled local RC, name the owner and compensating
controls, and require a transport change if the isolation evidence fails.
Keep #238 draft and #237/#232 open until the red check has an explicit,
reviewed disposition under repository policy. Do not change `ws://` to
`wss://` without a working TLS listener and verified certificate trust.

The internal `ws://` node links in the Compose and Helm configurations are
on isolated service networks, not public endpoints. Their inline Opengrep
exceptions are scoped to those exact links; verify Docker's internal bridge
and Helm's default-deny NetworkPolicy before relying on that disposition.
Do not use this exception for externally reachable WebSockets. Dynamic-regex
alerts must be checked against the caller's input domain: the restart evidence
path was changed to bounded filename parsing, while the Compact Nix canary
selects from a fixed platform list and the dependency refresher escapes
package names. These are not runtime actor inputs. The two portals render
untrusted values into HTML templates through an encoder for ampersands, angle
brackets, and both quote types. The applicant portal already tests a script
tag in a displayed DID; the admin console now tests that a malicious ledger
label and API error remain text nodes rather than creating an image element.
Those browser tests are regression evidence, not a proof that every future
template context is safe. Review the complete exact-head Opengrep report and
any newly added interpolation before disposition; this note does not waive
the scanner or independent human review.

Record the candidate source SHA, scan run URL, tool versions, complete
findings, and each disposition in the release evidence. Keep #198 draft if
the full scan fails or any high/critical finding lacks a defensible fix or
independent review.
