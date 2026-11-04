# UI acceptance for the local workspace

The admin console and applicant portal use one Midnight visual language: Outfit,
the approved logo, black/white/blue tokens, a shared task navigation frame, and
explicit source cues. The source cue is **Local fixture**, **API claim**, or
**Unavailable**. It never labels a browser response as independently finalized.

## UX Pilot comparison

The single [Midnight Trust Registry UX Pilot canvas](https://uxpilot.ai/a/ui-design?page=djbLMyF7a2TuLoSWYUwc)
contains the shared UI system, admin review workspace, applicant portal, mobile
portal, workspace settings, and exact local-ledger lookup. These are design
proposals, not evidence that a workflow is implemented or finalized.

| Design intent | Local implementation and acceptance |
| --- | --- |
| Lead with the next task, not a protocol field | The fixture portal puts its working demo application before governed role preparation in visual and keyboard order; the local-ledger portal leads to role choice. Admin headings distinguish pending decisions from a quiet review workspace. API editing lives under Connection and source details. `ui-layout.spec.mjs` and `demo-application-handoff.spec.mjs` check this hierarchy. |
| One Midnight visual language | Both apps use the approved logo, Outfit, black/white/blue tokens, and shared navigation/status components. |
| A compact review list with a bounded detail | Empty lifecycle lanes are omitted from the default admin view; selected detail stays beside the list on desktop and below it on mobile. |
| Truthful source and certainty | A visible source strip identifies fixture, API claim, or unavailable state and offers Recheck. Navigation follows the source: fixture demo and browse, exact lookup for local-ledger API claims, connection recovery when unavailable. Broad browse is omitted rather than shown as empty in local-ledger mode. Epoch and technical identity stay in details. No fixture record is called final. |
| Mobile task access | The desktop sidebar becomes a native keyboard-operable Menu at narrow widths. The mobile portal omits the nonessential snapshot card so the role path appears sooner; source status and Recheck remain visible. |

The canvas is a visual reference, not a complete behavior specification. Its
illustrative active issuer is not a real on-chain grant. A full assistive-technology
review, clean-checkout adoption trial, and deployed standalone actor E2E remain
separate acceptance work.

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
same-origin host; a separate cross-origin demo API does not enable them. A
same-origin URL check does not prove that a user session is authenticated; the
host must authenticate each private request.

## Browser acceptance

Run `pnpm run test:browser` in a clean checkout. It builds the prebuilt runtime
and runs the Playwright suite in Chromium with outbound browser requests denied
except for each test's allowlisted loopback host. The following cases are
repeatable UI acceptance evidence:

| Successful user path | Playwright evidence |
| --- | --- |
| Browse fixture records and review a bounded admin detail | `ui-layout.spec.mjs` |
| Submit a label-only issuer or recognition demo application in the portal, approve and activate it in admin, then read the active record back in the portal | `demo-application-handoff.spec.mjs` (two cross-app fixture journeys) |
| Choose issuer, verifier, auditor, or maintainer and complete challenge-bound evidence admission with an external signature | `applicant-portal.spec.mjs` (four role cases) |
| Confirm an issuer's proposed, authorized, active, suspended, revoked, and archived transitions with refreshed board status | `admin-console.spec.mjs` (fixture review journey) |
| Confirm fixture epoch publication, read back the exact new epoch, then submit an externally signed workspace intent against the refreshed context | `admin-console.spec.mjs` (fixture governance journey) |
| Revise a fixture maintainer threshold, see verifier registration remain required, and submit that registration separately | `admin-console.spec.mjs` (fixture policy journey) |
| Filter the fixture admin queue by text and lifecycle status before acting; filtered-out records cannot remain selected | `admin-console.spec.mjs`, admin unit tests |
| Recover an accepted proposal after its HTTP response is lost, without repeating the mutation | `governed-proposal-recovery.spec.mjs` (four role cases) |
| Submit an issuer proposal with two external maintainer signatures and a registered verifier signature, then read the direct accepted receipt without treating it as finality | `governed-proposal-recovery.spec.mjs` (Compact simulator and local admission host) |
| Complete a fixture recognition challenge, submit an external assertion, recover the accepted receipt, and download query-bound historical recognition and authorization API claims | `recognition-evidence.spec.mjs` (same-origin fixture session) |
| Edit either historical evidence query, discard its stale download, and keep the new draft through a source refresh | `recognition-evidence.spec.mjs` |
| Resolve exact current authorization and separate external recognition scopes in local-ledger mode; reject a substituted recognition tuple | `local-lookup.spec.mjs` (admin and applicant) |
| Inspect settings/source provenance, retry after an unavailable response, retain keyboard focus, and avoid overflow at 390/768/1440 px | `ui-layout.spec.mjs` |
| Show an operable Menu before the hero on mobile and align the task sidebar with the hero on desktop; place admin review counts beside the task introduction on wide screens and ahead of source details on mobile | `ui-layout.spec.mjs` (fresh-page geometry assertions) |
| Reject an external endpoint override on packaged same-origin admin and portal paths while preserving the authenticated-host warning | `ui-layout.spec.mjs` |
| Switch an editable development endpoint between two loopback fixture hosts without carrying reads to the old host or enabling cross-origin private actions | `ui-layout.spec.mjs` (both apps) |
| Open a governed issuer request by keyboard with reduced motion and verify the three visible preparation phases; keep mobile task targets at least 44 px high | `ui-layout.spec.mjs` |
| Reflow long identifiers and controls at 200% root text size on a 390 px viewport without page-level horizontal scroll | `ui-layout.spec.mjs` |
| Check browser-computed normal-text contrast for brand, navigation, source badge, and primary/secondary actions in both apps | `ui-layout.spec.mjs` (selected solid surfaces, at least 4.5:1) |
| Deny unapproved browser egress and discard stale local checkpoint responses | `browser-egress-control.spec.mjs`, `admin-console.spec.mjs` |

The role tests use a controlled local admission host, the cross-app handoff
and review journeys use fixture HTTP hosts, and local-ledger exact-lookup tests
use a controlled checkpoint stub. They exercise real Chromium interactions and response
handling, **not** a deployed Compact contract, authenticated finality, real
network isolation, or production security. A release-qualified standalone E2E
claim still requires the separately approved genesis/deployment, finalized
readback, egress-denied actor journeys, and restart/restore evidence.

## Final acceptance still to cover

The cross-app fixture journeys cover the remaining label-only demo and
recognition governance paths, but do not establish that *all* successful
deployed use cases work. The selected contrast samples do not replace a full
review of all states, overlays, and assistive technology. Each future case
must assert the exact source label, actor/action prerequisite, receipt or
board readback, and absence of false finality. Deployed standalone actor E2E
qualification remains a separate gate.

For visual review, run `TR_UI_CAPTURE=1 pnpm exec playwright test
browser-tests/ui-layout.spec.mjs` after building both UI packages. Inspect the
fresh-page screenshots in Playwright's `test-results/` at 390, 768, and 1440 px
for both apps; the capture occurs before scrolling so sticky navigation stays
in its true initial position. Check keyboard focus, long IDs, empty and
unavailable states, source language, and mobile task visibility against the
geometry assertions. Generated screenshots are local review artifacts, not
deployed acceptance evidence.

In the fixture admin workspace, use **Review records** to search by label,
role, or exact identifier and narrow by lifecycle status. Select a result to
see its bounded detail and available actions; a filter never submits a
mutation. Empty default status lanes do not precede populated results.
**Advanced governance** names the separate epoch, signed-intent,
proposal/recovery, and quorum/verifier tasks; each link opens a real task
section and retains its existing prerequisites. The local-ledger adapter has
no broad list, so its admin view keeps only exact-ID lookup. In the fixture
applicant portal, **Try the demo** submits a label-only request for
admin review; it never grants on-chain authority. For a governed request,
choose a role and complete the visible identify/scope/prepare phases. Sign the prepared digest
outside the browser and continue to one-use private evidence on the same-origin
authenticated host. A registered application is not an approved grant.

## Settings and trust language

Workspace settings expose endpoint, last browser check, source mode, registry
identity, and any approved local-plan digest reported by the API. Network
profile, genesis anchor, and contract identity are shown as *not exposed* when
the API does not return them. In local-ledger mode, the API's reported
checkpoint hash and timestamp are displayed separately from the browser check
time and explicitly remain unverified node claims. Same-origin packaged
endpoints are host-managed; the editable standalone development URL is not an
authentication mechanism.
No account avatar, private-key field, or browser-side deployment switch is
provided. Change deployment identity through reviewed operator configuration,
not a preference in the portal.
