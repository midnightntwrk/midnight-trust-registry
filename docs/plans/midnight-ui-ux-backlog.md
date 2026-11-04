# Midnight Trust Registry UI/UX adoption backlog

Status: proposed design and implementation plan, 2026-11-04. The UX Pilot
screens are concepts, not deployed UI or evidence of ledger finality.

Tracking issue: [#254](https://github.com/midnightntwrk/midnight-trust-registry/issues/254).
This document is the detailed acceptance map; GitHub issues are the execution
queue. Its local branch has not been pushed.

## Execution waves

| Wave | Owner issue | Deliverable | Gate before next wave |
| --- | --- | --- | --- |
| 1 | [#255](https://github.com/midnightntwrk/midnight-trust-registry/issues/255) | Shared Midnight UI primitives, responsive shells, and truthful source model | Unit and browser source-state tests, mobile/desktop layout, approved logo asset |
| 2a | [#256](https://github.com/midnightntwrk/midnight-trust-registry/issues/256) | Admin list/detail and named governance tasks | Existing admin actions remain reachable and fail closed |
| 2b | [#257](https://github.com/midnightntwrk/midnight-trust-registry/issues/257) | Applicant guided role/evidence flows | Four role paths and recovery tested; coordinate [#152](https://github.com/midnightntwrk/midnight-trust-registry/issues/152) |
| 3a | [#258](https://github.com/midnightntwrk/midnight-trust-registry/issues/258) | Workspace settings, not an account profile | Host-locked configuration and no secret/authority mutation |
| 3b | [#259](https://github.com/midnightntwrk/midnight-trust-registry/issues/259) | Local-ledger exact lookup | No broad-search or false-finality claims; coordinate [#219](https://github.com/midnightntwrk/midnight-trust-registry/issues/219) |
| 4 | [#260](https://github.com/midnightntwrk/midnight-trust-registry/issues/260) | Reviewed Playwright UX/accessibility baselines and adoption docs | Clean local walkthrough and light gate; coordinate [#59](https://github.com/midnightntwrk/midnight-trust-registry/issues/59) |
| Follow-up | [#261](https://github.com/midnightntwrk/midnight-trust-registry/issues/261) | Durable authenticated tracking/activity source | Do not expose tracker/activity links until the data contract exists |

Waves 2a/2b and 3a/3b can proceed in parallel after #255 if they use separate
branches and preserve the shared component contract. Review each wave with a
small UX acceptance pass before starting the next dependent slice. Do not
rewrite the entire UI in one PR.

## Design source and scope

Keep all MTR designs on the single [Midnight Trust Registry UX Pilot page](https://uxpilot.ai/a/ui-design?page=djbLMyF7a2TuLoSWYUwc).
It contains the shared UI system, admin review workspace, applicant desktop and
mobile entry, workspace settings, and local-ledger exact lookup. Do not create
another UX Pilot folder or page for this workstream.

The first implementation target is the self-hosted local/offline experience.
TLS, Preprod, and production account management are not part of this UI slice.
Use the approved Midnight SVG asset, Outfit, black `#0A0A0A`, white `#FFFFFF`,
and blue `#0000FE` from the [Midnight Brand Hub](https://midnight.network/brand-hub).
The schematic logo in UX Pilot is not an asset to copy into the repository.

## Product fit

| Journey | Current UI capability | Design fit and gap |
| --- | --- | --- |
| Inspect active issuer, verifier, auditor, and recognition records | Workspace lists and record details exist; current local-ledger mode exposes exact lookup instead | Desktop browse concept fits workspace mode only. The local-ledger screen must replace browse/search, not supplement it. Recognition stays distinct from local membership. |
| Apply for issuer, verifier, auditor, or maintainer membership | Separate forms, draft preparation, external signatures, and evidence submission exist | Role cards and a guided journey help, but must preserve exact resource, DID, key, scope, digest, and signature fields before submission. Do not turn these into an unverified one-click action. |
| Review and mutate a record | Admin board, detail, confirmation, and governed actions exist | List/detail layout removes overlap. Proposed, authorized, active, suspended, revoked, superseded, and archived states must remain visible and actionable only where permitted. |
| Govern policy and recognize external authorities | Proposal, threshold, verifier-registration, recognition, and recovery paths exist | Put these under clearly named secondary tasks. Preserve policy/sequence checks, external signatures, and fail-closed errors. |
| Export historical evidence | Workspace API exports authorization and recognition claims | Keep a separate evidence tool. The browser must not label API claims independently verified or current trust. |
| Track application or view complete activity | No confirmed general application tracker or complete action-history UI | The concept's “Track application” and “View activity” are future affordances. Replace them with existing exact-record lookup until a durable, authenticated status/history source exists. |
| Configure environment and actor | API URL is exposed; same-origin host can lock it. No authenticated account profile exists | Use **Workspace settings**, not a fake account avatar. Show source, mode, and deployment identity read-only. Never accept private keys or treat a selected role as authorization. |

## Prioritized delivery

### P0: shared contract and truthful source state

1. Extend `packages/trust-registry-ui` with reusable tokens and components for
   navigation, buttons, status/source badges, record summaries, bounded
   technical-ID disclosure, form feedback, empty states, and confirmation.
   Consume them from both apps; do not duplicate a second visual system.
2. Use the approved logo asset and Outfit locally. Keep high-contrast black,
   white, and blue; avoid decorative gradients that compete with evidence.
   Validate focused, hover, disabled, error, and reduced-motion states.
3. Build one explicit source model from API responses: workspace fixture,
   local-ledger current claim, unavailable, and independently verified finality
   only when such evidence actually exists. Show mode, endpoint health, and
   freshness without equating connectivity with trust or authorization.
4. Add a reusable responsive shell. Admin retains the clear left navigation;
   portal uses task-led navigation and a mobile menu. Navigation must keep
   labels and keyboard focus stable across rerenders.

Acceptance: no `kanon` copy; no unbounded IDs or overlapping panes at 390,
768, or 1440 px; source and finality labels are truthful in each mode; both
apps use the same component tokens and approved asset.

### P1: admin review and governance

1. Replace oversized lifecycle columns with a filterable list plus bounded
   detail pane. Keep every lifecycle state, role, recognition, decision reason,
   policy/epoch context, and archived evidence inspectable. Do not infer a
   human-readable scope from a hash or incomplete snapshot.
2. Move advanced governance to named secondary tasks: publish epoch, submit
   signed workspace intent, prepare/recover governed proposal, revise quorum,
   register evidence verifier, and maintain a scoped record. Keep exact-action
   confirmations and external signing context visible before every mutation.
3. Distinguish a local workspace mutation from a Compact/governed action and
   from finalized network evidence in success messages and activity summaries.

Acceptance: all current admin actions remain reachable; invalid/stale
signatures, policy changes, unavailable data, and rejected mutations never
display success; selected detail never covers another record.

### P1: applicant paths and evidence

1. Route role cards to the existing issuer, verifier, auditor, and maintainer
   forms. Introduce progressive steps for requirements, exact scope, evidence,
   digest/signing, and submitted receipt. Preserve prepared-context invalidation
   when inputs change; never collect a private key in the browser.
2. Separate local label-only demo submission from governed applications, with
   a persistent demo banner and distinct action text.
3. Preserve current exact authorization and recognition lookup in local-ledger
   mode. Keep historical authorization/recognition export in workspace mode;
   show its API-claim and independent-verification caveat beside results.
4. Give pending membership evidence, recognition accreditation, and ambiguous
   proposal recovery named entry points and explicit retry/no-retry states.

Acceptance: no use-case route disappears behind the landing page; every
disabled action explains its prerequisite; recognition is never represented as
local issuer/verifier membership; receipt recovery never resubmits a VP.

### P1: workspace settings, not a profile

1. Add a visible **Workspace settings** button to the admin shell. Provide
   connection health, API endpoint, source mode, last refresh, network profile,
   registry/contract identity, display preferences, and signing guidance.
2. In a same-origin host, show the API endpoint as host-managed and read-only.
   Editable local endpoints are a development-only capability and must not
   unlock private cross-origin actions. Show deployment/genesis identity as
   read-only; changing networks requires a reviewed deployment profile, not a
   browser preference.
3. Display an actor identity only when the host supplies authenticated identity
   and scope. Until then, do not show an account avatar, profile editor, role
   selector, key import, or a misleading “signed in” status.

Acceptance: settings cannot alter governance, approvals, quorum, registry ID,
genesis, or contract address; preferences are local-only; secrets never enter
UI state or persistence.

### P2: validation and adoption

1. Extend `browser-tests/ui-layout.spec.mjs` and task-flow Playwright suites
   with desktop, tablet, and mobile screenshots at 1440/768/390 px; keyboard
   traversal; visible focus; zoom and long-ID stress; error, empty, loading,
   stale, and denied states. Review screenshots rather than relying only on
   width assertions.
2. Exercise both fixture workspace and local-ledger modes, including source
   mismatch and partial API failure. Add accessibility checks for names,
   contrast, landmarks, form errors, and minimum targets. Keep offline browser
   egress restrictions in place.
3. Update quickstart, demo, adoption, and evidence docs with task-based
   walkthroughs and honest fixture-versus-deployed language. Test a new
   engineer following the instructions from a clean local setup.

Acceptance: focused unit/browser suites and the repository light gate pass;
visual baselines are reviewed; a new user can find each core task without raw
API knowledge. Fixture tests are not presented as deployed standalone E2E.

## Decisions and open dependencies

- **Profile versus settings:** ship settings now. A real profile requires a
  verified host identity model and is not implied by a browser session.
- **Search:** broad browse/search belongs to workspace mode. Local-ledger mode
  requires exact role/DID/resource or exact recognition scope until an
  authenticated index exists.
- **Application tracking/activity:** do not implement the concept's labels as
  dead links. Use existing exact lookup or defer until a durable authenticated
  status and action-history API exists.
- **Production trust:** signed genesis, pinned deployment, authenticated
  finalized readback, and independent security review remain separate release
  qualifications. UI polish must not claim to satisfy them.
