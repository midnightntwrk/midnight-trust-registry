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

## Inspect the remaining scanner output

The internal `ws://` node links in the Compose and Helm configurations are
on isolated service networks, not public endpoints. Their inline Opengrep
exceptions are scoped to those exact links; verify Docker's internal bridge
and Helm's default-deny NetworkPolicy before relying on that disposition.
Do not use this exception for externally reachable WebSockets. Dynamic-regex
alerts must be checked against the caller's input domain: the restart evidence
path was changed to bounded filename parsing, while the Compact Nix canary
selects from a fixed platform list and the dependency refresher escapes
package names. These are not runtime actor inputs. Other Opengrep findings,
including HTML rendering, still require review in the full exact-head report;
this note does not waive them.

Record the candidate source SHA, scan run URL, tool versions, complete
findings, and each disposition in the release evidence. Keep #198 draft if
the full scan fails or any high/critical finding lacks a defensible fix or
independent review.
