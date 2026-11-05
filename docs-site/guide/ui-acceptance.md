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
| Lead with the next task, not a protocol field | The default portal leads to governed role preparation. On loopback, `demo=1` opts into the label-only fixture application ahead of that path. Admin headings distinguish pending decisions from a quiet review workspace. API editing lives in the separate Workspace settings view. `ui-layout.spec.mjs` and `demo-application-handoff.spec.mjs` check this hierarchy. |
| Explain the applicant path before exposing forms | Four compact role choices lead to a role-specific disclosure. Choosing another card closes the previous role form and keeps the chosen card visibly selected; the selected form can also be collapsed. On a 390 px viewport each role stays under 95 px high and the full introductory section stays under 1050 px. A four-step guide explains choice, redacted evidence, external signing, and retaining the receipt; a prerequisite card calls out DID, exact scope, external keys, and authenticated host. A receipt is not approval, and opening a role does not submit it. |
| One Midnight visual language | Both apps use the approved logo, Outfit, black/white/blue tokens, and shared navigation/status components. The header groups the logo, Trust Registry title, and current portal/console context in one lockup instead of separating them across the bar. |
| Compact discovery and a bounded review detail | The fixture portal searches visible active records by name, role, scope, or DID without changing registry state. Empty lifecycle lanes are omitted from the admin view; selected detail stays beside the list on desktop and below it on mobile. The detail explains its source and lifecycle before the decision summary. Proposed and authorized records label their trust-level field as requested or authorized rather than displaying a bare value that could be mistaken for an approval decision. Exact IDs and external-signature preparation are separate disclosures. |
| Truthful source and certainty | A visible source strip identifies fixture, API claim, or unavailable state and offers Recheck. Navigation follows the source: optional fixture demo and browse, exact lookup for local-ledger API claims, connection recovery when unavailable. Local-ledger exact lookups precede membership preparation in DOM and visual order; unsupported broad lists are explained once, not shown as four failures or empty trust. The admin hero does not present counts of fetched exact results as registry-wide lifecycle totals; the applicant hero omits unavailable list totals and labels its epoch as API-reported. Actual failed fixture lists still show unavailable warnings. Empty fixture record categories are summarized instead of rendered as large cards; evidence/recovery tools are grouped under Advanced. Epoch and technical identity stay in details. No fixture record is called final. |
| Mobile and tablet task access | The desktop sidebar becomes a native keyboard-operable Menu at narrow widths. At 768 px, the portal keeps the full registry name on a separate line above compact metrics so governed requests begin in the first viewport; on small phones it omits the nonessential snapshot card so the role path appears sooner. Source status and Recheck remain visible. |

The canvas is a visual reference, not a complete behavior specification. Its
illustrative active issuer is not a real on-chain grant. A full assistive-technology
review, clean-checkout adoption trial, and deployed standalone actor E2E remain
separate acceptance work.

Issuer screens say **credential scope** rather than "credential family". The
existing `credentialFamilyId` and `credentialFamily` wire fields remain unchanged
for compatibility with signed scope commitments and current API clients; a
protocol rename requires a separately reviewed migration.

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

Open the ordinary admin console at `http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400`
and applicant portal at `http://127.0.0.1:4175/?apiBase=http://127.0.0.1:4400`.
To exercise label-only fixture submission and local admin shortcut controls,
add `demo=1` to each URL, for example
`http://127.0.0.1:4175/?demo=1&apiBase=http://127.0.0.1:4400`.
The presentation flag is accepted only on a loopback UI origin. It does not
authorize mutations: the API must separately be started with
`--unsafe-demo-mutations` on loopback. Do not expose a demo workspace to users.
The demo API command starts a local fixture workspace with unsafe demo mutations;
do not expose these ports beyond loopback or interpret its records as deployed
ledger state. The source panel and Workspace settings disclose that distinction.
If those ports are already in use, keep the prepared workspace and start the
three built servers on unused loopback ports instead:

```bash
node packages/trust-registry-api/bin/trust-registry-api.mjs serve --workspace ./artifacts/trust-registry/midnight-demo-workspace.json --unsafe-demo-mutations --port 4442
PORT=4187 node packages/trust-registry-admin-console/scripts/serve.mjs
PORT=4189 node packages/trust-registry-applicant-portal/scripts/serve.mjs
```

Use the selected API port in both `apiBase` URL parameters. Each command needs
its own terminal. These alternate ports do not make a fixture deployment-safe.
The portal's governed private-evidence actions require an authenticated
same-origin host; a separate cross-origin demo API does not enable them. A
same-origin URL check does not prove that a user session is authenticated; the
host must authenticate each private request.

### Clean-checkout smoke record

On 2026-11-04, an agent repeated the trial in a detached clean checkout at
`45d5d7f8` with no pre-existing generated contract output. `pnpm install --frozen-lockfile`,
`pnpm run build:light` (10 uncached tasks), and `pnpm run demo:prepare` passed.
With the existing demo still on the default ports, the clean API ran on 4442
using its CLI `--port` option, while `PORT=4187` and `PORT=4189` selected the
admin and portal static-server ports. Chromium submitted a label-only issuer
application, found it in admin, approved and activated it, and read the active
record back in the portal. The source remained **Local fixture** throughout.
This was an agent-run setup check, not an independent new-engineer trial or a
deployed-ledger end-to-end result.

On 2026-11-05, the same clean-checkout setup was repeated at signed source
`c7c599ca` on isolated ports 4442/4187/4189. Frozen install, all 10 uncached
light-build tasks, and `demo:prepare` passed. In Chromium, an issuer fixture
application submitted in the portal appeared as Proposed in admin, moved to
Authorized and Active through confirmed local-fixture actions, and appeared in
the portal's active issuer list after a reload. The confirmation copy needed a
follow-up: fixture actions now say "in demo" and explicitly distinguish their
effect from a deployed-ledger action. This remains an agent-run fixture trial,
not a new-engineer or deployed standalone acceptance result.

## Browser acceptance

Run `pnpm run test:browser` in a clean checkout. It builds the prebuilt runtime
and runs the Playwright suite in Chromium with outbound browser requests denied
except for each test's allowlisted loopback host. The following cases are
repeatable UI acceptance evidence:

| Successful user path | Playwright evidence |
| --- | --- |
| Browse fixture records and review a bounded admin detail; keyboard selection retains focus and identifies the current card and detail pane | `ui-layout.spec.mjs` |
| Search the fixture portal by DID, see an explicit no-match state, and return to a visible record; keep the admin signing controls collapsed until requested | `ui-layout.spec.mjs` |
| Submit a label-only issuer or recognition demo application in the portal, approve and activate it in admin, then read the active record back in the portal | `demo-application-handoff.spec.mjs` (two cross-app fixture journeys) |
| Identify fixture-only admin actions before clicking, and confirm the exact record without implying an on-chain grant | `demo-application-handoff.spec.mjs`, admin model and app tests |
| Choose issuer, verifier, auditor, or maintainer and complete challenge-bound evidence admission with an external signature | `applicant-portal.spec.mjs` (four role cases) |
| Expose applicant source and historical/evidence failures as alert regions, and accepted application, evidence, recognition-recovery, and admin-action receipts as polite status regions | `ui-layout.spec.mjs`, `applicant-portal.spec.mjs`, `recognition-evidence.spec.mjs`, `admin-console.spec.mjs`, applicant unit tests |
| Choose each applicant role card by keyboard, keep only its governed form open, expose expanded state to assistive technology, retain the selected role after recheck, and make no submission merely by choosing | `ui-layout.spec.mjs` |
| Confirm an issuer's proposed, authorized, active, suspended, revoked, and archived transitions with refreshed board status | `admin-console.spec.mjs` (fixture review journey) |
| Confirm fixture epoch publication, read back the exact new epoch, then submit an externally signed workspace intent against the refreshed context | `admin-console.spec.mjs` (fixture governance journey) |
| Revise a fixture maintainer threshold, see verifier registration remain required, and submit that registration separately | `admin-console.spec.mjs` (fixture policy journey) |
| Filter the fixture admin queue by text and lifecycle status before acting; filtered-out records cannot remain selected | `admin-console.spec.mjs`, admin unit tests |
| Recover an accepted proposal after its HTTP response is lost, without repeating the mutation | `governed-proposal-recovery.spec.mjs` (four role cases) |
| Submit an issuer proposal with two external maintainer signatures and a registered verifier signature, then read the direct accepted receipt without treating it as finality | `governed-proposal-recovery.spec.mjs` (Compact simulator and local admission host) |
| Complete a fixture recognition challenge, submit an external assertion, recover the accepted receipt, and download query-bound historical recognition and authorization API claims | `recognition-evidence.spec.mjs` (same-origin fixture session) |
| Edit either historical evidence query, discard its stale download, keep the new draft through a source refresh, and restore submit-button focus after a response or rejected exact tuple | `recognition-evidence.spec.mjs`, applicant unit tests |
| Choose one local-ledger applicant task at a time: current authorization or external recognition. Keep the selected form and its prior result when switching tasks or returning from settings; never issue a lookup merely by switching. Resolve exact scopes, reject a substituted recognition tuple, preserve a malformed-context draft and keyboard focus, announce errors/results, and copy the exact returned claim with an unverified-source warning | `local-lookup.spec.mjs` (admin and applicant) |
| Keep registry-wide lifecycle counters off the local-ledger admin hero before and after an exact lookup; a fetched record is not a complete registry count | `local-lookup.spec.mjs` |
| Show only registry identity and an API-reported epoch in the local-ledger applicant overview, not unavailable issuer/verifier list totals | `local-lookup.spec.mjs` |
| Discard a previously visible API claim while Recheck is pending, remove exact lookup when the source becomes a fixture, and never reuse the old result when local-ledger mode returns; a denied follow-up lookup clears the prior success and announces the denial | `local-lookup.spec.mjs` (admin and applicant, controlled source switch and 403) |
| Show approved local-plan network and deployment identity only as API-reported values in Workspace settings; remove them when the source becomes a fixture or the API omits identity. Keep long genesis and contract hashes behind an accessible technical disclosure and both settings views within 320 px at 200% root text size, including when expanded | `local-lookup.spec.mjs` (both apps); API and client unit tests reject malformed or unapproved identity |
| Inspect settings/source provenance, expose an offline error as an alert, retry after an unavailable response, retain keyboard focus, and avoid overflow at 320/390/768/1440 px | `ui-layout.spec.mjs` |
| Open the mobile Menu and Workspace settings by keyboard in both apps; verify the URL field and recheck action have accessible names and retain focus after refresh | `ui-layout.spec.mjs` |
| Show an unavailable auditor list as unavailable rather than zero, keep loaded issuers visible, and recover the lane after recheck | `ui-layout.spec.mjs` (controlled partial-failure fixture) |
| During Recheck, label the admin's last-loaded records as potentially stale with actions paused, hide portal records until the response arrives, then show an offline error without stale trust data and recover on a later successful check | `ui-layout.spec.mjs` (held health response, both apps) |
| Show an operable Menu before the hero on mobile and align the task sidebar with the hero on desktop; place fixture admin review counts beside the task introduction on wide screens and ahead of source details on mobile | `ui-layout.spec.mjs` (fresh-page geometry assertions) |
| Reject an external endpoint override on packaged same-origin admin and portal paths while preserving the authenticated-host warning | `ui-layout.spec.mjs` |
| Switch an editable development endpoint between two loopback fixture hosts without carrying reads to the old host or enabling cross-origin private actions | `ui-layout.spec.mjs` (both apps) |
| Open a governed issuer request by keyboard with reduced motion and verify the three visible preparation phases; keep mobile task targets at least 44 px high | `ui-layout.spec.mjs` |
| Keep the 390 px applicant introduction compact without hiding role requirements or implying that submission is approval | `ui-layout.spec.mjs` (role-row and section-height assertions, visible prerequisite text) |
| Choose a label-only demo application type with visible radio options and keyboard navigation; retain the selection and avoid horizontal overflow at 200% mobile text size | `demo-application-handoff.spec.mjs`, `ui-layout.spec.mjs` |
| Keep label-only application, fixture lifecycle mutations, epoch publication, and signed workspace intent out of the ordinary UI; show them only with the loopback `demo=1` presentation flag on a fixture source. An API-claimed local ledger still suppresses fixture controls when the flag is requested. Merely switching views must not submit a mutation | `ui-layout.spec.mjs`, `local-lookup.spec.mjs` (both apps) |
| Carry issuer and recognition fixture applications through both browser UIs against the packaged workspace API and a private temporary workspace, with demo controls absent before `demo=1`. Verify Proposed → Authorized → Active and the exact record in the API's active list; delete only the test-owned workspace afterward | `workspace-api-handoff.spec.mjs` (real packaged API, still fixture-only and not deployed E2E) |
| Reflow at 200% root text size on 320/390 px viewports without page-level horizontal scroll or non-control internal overlap; check workspace, advanced, and settings views at 320 px. Long text inside native inputs may scroll within the control. | `ui-layout.spec.mjs` |
| Reflow local-ledger exact lookup at 320 px and 200% root text size in both apps, including returned records and expanded technical details; keep API-claim labels and avoid page-level overflow. Raw JSON scrolls inside a bounded, keyboard-focusable region rather than becoming a wall of broken words | `local-lookup.spec.mjs` |
| Check browser-computed normal-text contrast for the brand lockup, navigation, source badge, and primary/secondary actions in both apps | `ui-layout.spec.mjs` (selected solid surfaces, at least 4.5:1) |
| Audit rendered workspace, expanded workflow, settings, and unavailable-source views, plus 390 px local-ledger results and settings, for automated WCAG 2.0/2.1/2.2 A/AA violations | `ui-layout.spec.mjs`, `local-lookup.spec.mjs` (`@axe-core/playwright`, no external browser requests) |
| Serve the shared Midnight browser icon from each built app without a missing-resource response | `ui-layout.spec.mjs` |
| Deny unapproved browser egress and discard stale local checkpoint responses | `browser-egress-control.spec.mjs`, `admin-console.spec.mjs` |

### Visual review record

On 2026-11-05, the applicant portal's 768 px capture was re-reviewed with the
long `Midnight Trust Registry` fixture label. Four equal tiles made that name a
three-line card beside three tall empty-looking metric cards. The tablet
snapshot now puts the full registry name on its own line and balances epoch,
issuer, and verifier metrics below it; the governed-request heading remains in
the first viewport. The 390 px portal and admin, 768 px admin, and 1440 px
desktop views were also inspected. This is visual fixture evidence, not a
deployed-ledger walkthrough or independent user trial.

On 2026-11-04, the locally built fixture admin and applicant pages were
visually inspected as full-page captures at 1440, 768, and 390 px. The product
title and workspace label stay together; the 768 px sidebar and record detail
do not overlap; mobile role choices and source labels remain legible. That pass
found raw ISO source timestamps and singular record counts with plural labels;
both were corrected and covered by UI tests. This is an agent-run visual pass,
not an independent new-user or assistive-technology review. The capture does
not establish deployed-ledger behavior.

A separate controlled local-ledger capture was inspected at 390 px in both
apps and at 768/1440 px in the portal. The applicant chooses authorization or
external recognition without showing both long forms at once. The exact query
and its result/interpretation appear side by side on desktop and stack on
mobile; before a query, the result says that no record is loaded. Results retain
the **unverified API claim** label and the
independent-finality warning. The settings review at 390 px exposed another
raw browser timestamp; settings now show the same readable UTC time as the
source strip. These captures use a stubbed checkpoint, not a deployed contract.

The automated axe checks are a repeatable baseline. They cannot establish that
the flow is understandable with a screen reader, that keyboard order is useful
for every action, or that every dynamic state has been sampled. Keep the
assistive-technology and visual review open rather than treating zero reported
violations as full accessibility certification.

The role tests use a controlled local admission host, the cross-app handoff
and review journeys use fixture HTTP hosts, and local-ledger exact-lookup tests
use a controlled checkpoint stub. They exercise real Chromium interactions and response
handling, **not** a deployed Compact contract, authenticated finality, real
network isolation, or production security. A release-qualified standalone E2E
claim still requires the separately approved genesis/deployment, finalized
readback, egress-denied actor journeys, and restart/restore evidence.

The `demo=1` browser case checks presentation only. It does not prove that a
non-demo API rejects fixture mutations; server-side authorization and the
loopback-only unsafe-mutation option are separate controls.

On 2026-11-05, fresh full-page fixture captures at 1440 and 390 px were
reviewed in both apps at signed source `f1497d74`. The shared brand lockup,
source warning, and primary task remain visible; the mobile admin detail follows
the selected record instead of covering it, and Workspace settings separates
connection identity from the main applicant journey. The applicant's exact
local-ledger result was also inspected at 320 px with 200% root text: its
interpretation text reflows and the raw JSON stays in a bounded keyboard-
focusable scroll region. These agent-reviewed captures do not substitute for
an independent new-user or assistive-technology trial.

## Clean-checkout reproducibility trial

On 2026-11-04, an agent used a disposable detached worktree at signed source
`666e5ffc8827f5003f50f1836db6f46f281c1f90`, without copying generated
artifacts from the development checkout. With Node.js 24.14.0 and pnpm 10.34.1:

```bash
pnpm install --frozen-lockfile
./run.sh --light
pnpm run demo:smoke
pnpm exec playwright test
```

The frozen install succeeded, the light gate completed 20/20 tasks (including
198/198 adversarial cases), the CLI/API/two-UI smoke passed on ephemeral
loopback ports, and Playwright passed 41/41 browser tests. This verifies the
scripted local fixture path at that exact source. It is **not** a new engineer's
independent usability trial, a deployed standalone actor run, or proof of
authenticated finality. Keep those acceptance items open.

On 2026-11-05, the same agent repeated the frozen install, full light gate,
and ephemeral-port `demo:smoke` in a new detached worktree at signed source
`22eaee057538ea58beda8c8878093644e060fd3c`. The 20/20 light tasks,
198-case adversarial parity, and both served UI surfaces passed. The 42/42
Playwright browser suite passed at that source in the development worktree.
This is a second reproducibility check, not an independent new-user trial or
deployed-ledger E2E acceptance.

At signed source `f1497d74ed7bcd07052297942ef45a5229ce37b8`, a fresh
detached checkout with frozen dependencies passed `./run.sh --light` (20/20
tasks and 198/198 adversarial parity), packed-consumer smoke, and
`pnpm run demo:smoke` on ephemeral loopback ports. The development worktree's
44/44 Playwright tests passed at the same source. The disposable checkout and
its reproducible light outputs were removed after inspection. This confirms
the scripted fixture setup at that source, not independent adoption or a
deployed-ledger journey.

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
fresh-page screenshots in Playwright's `test-results/` at 320, 390, 768, and 1440 px
for both apps; the capture occurs before scrolling so sticky navigation stays
in its true initial position. Run `TR_UI_CAPTURE=1 pnpm exec playwright test
browser-tests/local-lookup.spec.mjs` for local-ledger result and settings captures
at 390, 768, and 1440 px. Check keyboard focus, long IDs, empty and
unavailable states, source language, and mobile task visibility against the
geometry assertions. Generated screenshots are local review artifacts, not
deployed acceptance evidence.

In the fixture admin workspace, use **Review records** to search by label,
role, or exact identifier and narrow by lifecycle status. Select a result to
see what its lifecycle means before opening exact identifiers or preparing an
external-signature action. The primary date is formatted in UTC; the exact
API timestamp remains under Identifiers and evidence. A filter never submits
a mutation. Empty default status lanes do not precede populated results.
**Advanced governance** names the separate epoch, signed-intent,
proposal/recovery, and quorum/verifier tasks; each link opens a real task
section and retains its existing prerequisites. The local-ledger adapter has
no broad list, so its admin view keeps only exact-ID lookup. In the fixture
applicant portal, **Try the demo** submits a label-only request for
admin review; it never grants on-chain authority. Its three application types
are visible choices rather than a browser-native dropdown, so the selected
type remains clear before submission. For a governed request,
choose a role, check the four-step path and prerequisites, and complete the
visible identify/scope/prepare phases. In the fixture view, active-record
search filters only the displayed snapshot; it is not an authorization query
or independent trust verification. Sign the prepared digest
outside the browser and continue to one-use private evidence on the same-origin
authenticated host. A registered application is not an approved grant.

## Settings and trust language

The sidebar or mobile Menu opens a dedicated Workspace settings view. The main
workspaces retain a compact source-status cue, but the detailed connection form
and deployment identity do not compete with record workflows. Settings expose
endpoint, last browser check, source mode, registry label, and a short
deployment summary. Exact registry IDs, DID, epoch, plan digest, checkpoint,
network ID, expected genesis hash, and contract address are available in a
keyboard-accessible **Technical identifiers and plan** disclosure rather than
dominating the initial view. Network profile and identity values are shown
only when the approved local-ledger API returns a deployment identity from its
plan; otherwise they are shown as *not exposed*. These are API-reported plan
values, not independent browser verification of the chain or contract. In
fixture mode, settings explicitly say there is no deployment plan; when the
source is unavailable, they do not infer any deployment identity. The local
plan notice appears only when the local-ledger API exposes one. In
local-ledger mode, the API's reported
checkpoint hash and timestamp are displayed separately from the browser check
time and explicitly remain unverified node claims. Same-origin packaged
endpoints are host-managed; the editable standalone development URL is not an
authentication mechanism.
No account avatar, private-key field, or browser-side deployment switch is
provided. Change deployment identity through reviewed operator configuration,
not a preference in the portal.
