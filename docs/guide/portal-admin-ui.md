# Portal and admin UI

The applicant portal and admin console are two views of the same Midnight
Trust Registry. They share a small offline-first presentation layer in
`packages/trust-registry-ui`: Midnight color tokens, the locally bundled Outfit
font, the Midnight wordmark, navigation, focus styles, and technical-ID rules.
Each app copies those assets into its own static distribution, so a standalone
installation does not request fonts or images from the public internet.

The palette and type choice follow the [Midnight Brand Hub](https://midnight.network/brand-hub).
The wordmark is reused from the sibling Midnight DID documentation site. The
apps retain separate task-specific layouts and forms; shared tokens should not
force applicant and maintainer workflows into one generic component.

## Interaction model

- Applicant portal: inspect active records, try a clearly marked local fixture
  application, or expand one governed membership workflow. The evidence panel
  opens automatically when a pending application needs the next action.
- Admin console: inspect the review board and selected record first. Long IDs
  live in a disclosure; policy and signing workflows live in an advanced
  section. Local fixture controls remain visibly distinct from Compact quorum
  actions.
- Exact IDs are never truncated in detail or signed data. They wrap in their
  containers; the current epoch is summarized as a count with its full ID
  beneath it. No UI label is proof of ledger finality.

## UI audit

From a clean, **disposable** checkout with Node.js 24, pnpm, the pinned
Compact compiler, and Playwright Chromium installed:

```sh
pnpm install --frozen-lockfile
pnpm run check:compact-installed
pnpm run build:light
pnpm exec playwright test browser-tests/ui-layout.spec.mjs \
  browser-tests/admin-console.spec.mjs browser-tests/applicant-portal.spec.mjs \
  browser-tests/local-lookup.spec.mjs browser-tests/demo-application-handoff.spec.mjs
```

`build:light` replaces generated `dist` outputs. Never run it in a checkout
holding irreplaceable Compact keys, install bundles, or private setup
evidence. The browser tests start their own loopback fixture hosts; no live
node, API token, or pre-existing demo service is required. The offline-browser
fixture rejects external requests. A passing run checks task navigation,
selected-record details, empty versus unavailable source states, the
applicant-to-admin fixture handoff, long IDs, keyboard focus, text zoom, and
automated WCAG A/AA rules. It covers the
desktop layout at 1440 px and responsive layouts at 768 and 390 px; the
320 px stress checks are retained as regression evidence, not a mobile-device
acceptance claim.

Set `TR_UI_CAPTURE=1` for screenshots in the ignored `test-results` directory.
Review the desktop workspace, open workflow, settings, and local exact-lookup
screens visually; width and axe assertions do not detect confusing task order
or every overlap. A manual keyboard and assistive-technology pass is still
separate from automated accessibility evidence.

The two source paths must not be conflated:

| Source | What the UI offers | What the label proves |
| --- | --- | --- |
| Local workspace fixture | Review board, active lists, and explicitly marked demo shortcuts when enabled | Only that a loopback fixture API responded |
| Local-ledger API claim | Exact current authorization or recognition lookup; no broad list or fixture mutation controls | Only that the API reported a current claim, not independently authenticated finality |
| Unavailable or partial response | Error/retry guidance; stale records are cleared or marked unavailable | No current trust decision |

This audit is not a deployed standalone end-to-end qualification. It uses a
local fixture HTTP server and does not establish contract finality, human
security approval, or VC-owned status authority.
