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
`artifacts/trust-registry/guided-role-demo-workspace.json`; restarting the
command keeps it. Stop both services with Ctrl+C.

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

The profile switcher is navigation, **not identity authentication**. Votes
are in this browser's local storage and can be reset. The majority is a
teaching aid; the fixture API itself does not enforce it. Do not cite this
demo as evidence of Compact quorum, external maintainer signatures, network
finality, or production authorization. For real governance, use the technical
admin console and an approved signed deployment.
