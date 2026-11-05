# UI acceptance for the local workspace

The admin console and applicant portal use one Midnight visual language: Outfit,
the approved logo, black/white/blue tokens, a shared task navigation frame, and
explicit source cues. The source cue is **Local fixture**, **API claim**, or
**Unavailable**. It never labels a browser response as independently finalized.

## Run locally

From a clean Trust Registry checkout with Node 24, pnpm 10, and the pinned
Compact toolchain:

```bash
pnpm install --frozen-lockfile
pnpm run build:light
pnpm run demo:prepare
pnpm run demo:serve:api
# In separate terminals:
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

Open the admin console at `http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400`
and the applicant portal at `http://127.0.0.1:4175/?apiBase=http://127.0.0.1:4400`.
The default demo API is a local fixture workspace with unsafe demo mutations;
do not expose these ports beyond loopback or interpret its records as deployed
ledger state. The source panel and Workspace settings disclose that distinction.
The portal's governed private-evidence actions require an authenticated
same-origin host; a separate cross-origin demo API does not enable them.

## Browser acceptance

Run `pnpm run test:browser` in a clean checkout. It builds the prebuilt runtime
and runs the Playwright suite in Chromium with outbound browser requests denied
except for each test's allowlisted loopback host. The following cases are
repeatable UI acceptance evidence:

| Successful user path | Playwright evidence |
| --- | --- |
| Browse fixture records and review a bounded admin detail | `ui-layout.spec.mjs` |
| Choose issuer, verifier, auditor, or maintainer and complete challenge-bound evidence admission with an external signature | `applicant-portal.spec.mjs` (four role cases) |
| Confirm proposed issuer approval, then activation, and refresh the board | `admin-console.spec.mjs` (fixture review journey) |
| Recover an accepted proposal after its HTTP response is lost, without repeating the mutation | `governed-proposal-recovery.spec.mjs` (four role cases) |
| Resolve one exact current authorization in local-ledger mode without broad-list or fixture controls | `local-lookup.spec.mjs` (admin and applicant) |
| Inspect settings/source provenance, retry after an unavailable response, retain keyboard focus, and avoid overflow at 390/768/1440 px | `ui-layout.spec.mjs` |
| Deny unapproved browser egress and discard stale local checkpoint responses | `browser-egress-control.spec.mjs`, `admin-console.spec.mjs` |

The role tests use a controlled local admission host, the review journey uses a
fixture HTTP host, and local-ledger exact-lookup tests use a controlled
checkpoint stub. They exercise real Chromium interactions and response
handling, **not** a deployed Compact contract, authenticated finality, real
network isolation, or production security. A release-qualified standalone E2E
claim still requires the separately approved genesis/deployment, finalized
readback, egress-denied actor journeys, and restart/restore evidence.

## Settings and trust language

Workspace settings expose endpoint, last browser check, source mode, registry
identity, and any approved local-plan digest reported by the API. Network
profile, genesis anchor, and contract identity are shown as *not exposed* when
the API does not return them. Same-origin packaged endpoints are host-managed;
the editable standalone development URL is not an authentication mechanism.
No account avatar, private-key field, or browser-side deployment switch is
provided. Change deployment identity through reviewed operator configuration,
not a preference in the portal.
