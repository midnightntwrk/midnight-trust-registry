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

Run `pnpm exec playwright test browser-tests/ui-layout.spec.mjs` after building
both UI packages. The offline-browser fixture rejects external requests. It
checks the wordmark, representative long registry/epoch/DID/resource values,
selected-record detail, and horizontal overflow at 1440, 768, and 390 pixels.
Set `TR_UI_CAPTURE=1` to save desktop and mobile screenshots in Playwright's
ignored `test-results` directory for visual review. Also run the applicant
and admin browser flow specs to catch disclosure or focus regressions.

This audit is not a deployed standalone end-to-end qualification. It uses a
local fixture HTTP server and does not establish contract finality, human
security approval, or VC-owned status authority.
