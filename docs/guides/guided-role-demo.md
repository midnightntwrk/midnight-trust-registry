# Guided local role demo

This is a **fixture exercise**, not a deployed Midnight Trust Registry or a
cryptographic committee. It is for trying the issuer, verifier, auditor and
maintainer journeys without signing keys or a ledger.

From a standalone checkout, install dependencies once and run:

```bash
pnpm install --frozen-lockfile
pnpm demo:guided
```

Open the URL printed by the command, normally
`http://127.0.0.1:4273/demo.html?apiBase=http%3A%2F%2F127.0.0.1%3A4500`.
Both services bind to loopback. The dedicated fixture file is
`artifacts/trust-registry/guided-role-demo-v2-workspace.json`; restarting the
command keeps it. An older `guided-role-demo-workspace.json` is left intact,
but is not used by this route. Stop both services with Ctrl+C.

## How the demo is built

```text
Browser at 127.0.0.1:4273
  |-- static /demo.html from the admin-console package
  |-- persona navigation and 3-of-5 practice votes in browser localStorage
  `-- HTTP reads and explicit fixture actions --> API at 127.0.0.1:4500
                                                `-- dedicated operator-workspace JSON file
```

`pnpm demo:guided` checks that a prebuilt Compact source copy matches the
checked-out source, builds the TypeScript and UI workspaces, initializes
the dedicated workspace file if absent, and starts the two loopback servers.
On a fresh checkout, compiling the Compact contract can take several minutes.
The guided page is a separate route in the admin-console package; it does not
replace the applicant portal or technical admin console.

The browser reads the registry summary and authorization lists through the
local API. Issuer, verifier, and auditor personas send **label-only** practice
applications. The API writes Proposed records to the dedicated workspace.
Maintainer #1 through #5 are navigation personas, not authenticated people or
keys. Their votes are stored in this browser, scoped to the registry, record,
status, and update time. After three matching votes, **Apply** asks for
confirmation, rereads the current board, and calls the fixture API. Approval
moves Proposed to Authorized; a second vote round can move Authorized to
Active. Rejection archives a Proposed record. The API does not verify or
enforce the browser vote tally.

The demo page enables submissions and votes only when both origins are HTTP
loopback and the API reports the dedicated `workspace` with registry label
`guided-role-demo` and ID `registry:guided-role-demo:trusted`. Other mutable
workspaces, memory, snapshot and `local-ledger` sources are read-only here.
Only issuer, verifier, and auditor records enter the guided inbox; recognition
records remain in the technical admin console. Unknown API record statuses
disable the guided page rather than rendering as HTML. This identity check
prevents accidental cross-workspace actions, but is not authentication of a
malicious loopback service. The launcher passes
`--unsafe-demo-mutations` to the workspace API, which itself requires a
loopback host. No genesis approval, deployed contract, signed committee
action, authenticated finality, or VC proof is involved in this journey.

The existing production-oriented components have different responsibilities:
the domain and Compact packages define governed state and transitions; the
client and API project/query trust evidence; an approved local-ledger runtime
needs a signed plan and external signer/finality inputs. The guided demo is
not a shortcut around those requirements. See
[architecture boundaries](../architecture/trust-registry-boundaries.md) and
the [published architecture overview](../../docs-site/architecture/index.md).

## Walkthrough

1. Select **Issuer #1** in the left navigation, enter a recognizable display
   name and send a demo request. The request starts as **Proposed**.
2. Select **Switch to Maintainer #1**. Open the request in the inbox, inspect it and
   choose **Approve in demo** or **Reject in demo**.
3. Follow **Continue as Maintainer #2** and **Continue as Maintainer #3** to collect a 3-of-5
   majority. Each persona gets one browser-local vote per request stage.
4. Select **Apply authorization to demo**. This updates the local fixture
   from Proposed to Authorized. A fresh vote round is required for activation.
5. Repeat with three maintainers and select **Apply activation to demo**.
   Switch back to **Issuer #1** to see the Active fixture record.
6. Try **Verifier #1** or **Auditor #1** in the same way. A rejection majority
   archives a proposed fixture request; it is not a signed denial ceremony.

**Clear browser demo votes** removes vote progress but leaves fixture records
unchanged. Restarting the command also keeps records. For a fresh walkthrough,
stop the services and archive or rename the dedicated workspace file before
restarting; do not delete another operator workspace. Do not cite this demo
as evidence of Compact quorum, external maintainer signatures, network
finality, or production authorization. For real governance, use the technical
admin console with an approved signed deployment and its required external
services.
