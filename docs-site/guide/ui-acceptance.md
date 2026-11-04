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
| Confirm an issuer's proposed, authorized, active, suspended, revoked, and archived transitions with refreshed board status | `admin-console.spec.mjs` (fixture review journey) |
| Filter the fixture admin queue by text and lifecycle status before acting; filtered-out records cannot remain selected | `admin-console.spec.mjs`, admin unit tests |
| Recover an accepted proposal after its HTTP response is lost, without repeating the mutation | `governed-proposal-recovery.spec.mjs` (four role cases) |
| Resolve exact current authorization and separate external recognition scopes in local-ledger mode; reject a substituted recognition tuple | `local-lookup.spec.mjs` (admin and applicant) |
| Inspect settings/source provenance, retry after an unavailable response, retain keyboard focus, and avoid overflow at 390/768/1440 px | `ui-layout.spec.mjs` |
| Reject an external endpoint override on packaged same-origin admin and portal paths while preserving the authenticated-host warning | `ui-layout.spec.mjs` |
| Open a governed issuer request by keyboard with reduced motion and verify the three visible preparation phases; keep mobile task targets at least 44 px high | `ui-layout.spec.mjs` |
| Reflow long identifiers and controls at 200% root text size on a 390 px viewport without page-level horizontal scroll | `ui-layout.spec.mjs` |
| Deny unapproved browser egress and discard stale local checkpoint responses | `browser-egress-control.spec.mjs`, `admin-console.spec.mjs` |

The role tests use a controlled local admission host, the review journey uses a
fixture HTTP host, and local-ledger exact-lookup tests use a controlled
checkpoint stub. They exercise real Chromium interactions and response
handling, **not** a deployed Compact contract, authenticated finality, real
network isolation, or production security. A release-qualified standalone E2E
claim still requires the separately approved genesis/deployment, finalized
readback, egress-denied actor journeys, and restart/restore evidence.

## Final acceptance still to cover

The browser suite is not yet a pass for *all* successful UI use cases. Before
closing the UI acceptance issue, Playwright must also exercise a successful
fixture epoch publication and signed workspace intent; the threshold revision
and separate evidence-verifier registration; a successful governed proposal
with external quorum; recognition accreditation and historical evidence
export; and editable loopback endpoint settings. Add reviewed contrast checks.
Each test must
assert the exact source label, actor/action prerequisite, receipt or board
readback, and absence of false finality. Deployed standalone actor E2E
qualification remains a separate gate even after these browser cases pass.

In the fixture admin workspace, use **Review records** to search by label,
role, or exact identifier and narrow by lifecycle status. Select a result to
see its bounded detail and available actions; a filter never submits a
mutation. **Advanced governance** names the separate epoch, signed-intent,
proposal/recovery, and quorum/verifier tasks; each link opens a real task
section and retains its existing prerequisites. The local-ledger adapter has
no broad list, so its admin view keeps only exact-ID lookup. In the applicant
portal, choose a role first, then complete the visible
identify/scope/prepare phases. Sign the prepared digest
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
