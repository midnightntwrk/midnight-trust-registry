import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { ACCEPTANCE_CASES } from "./standalone-acceptance-manifest-policy.mjs";

const guide = new URL("../docs/guide/standalone-local-journey.md", import.meta.url);

test("operator acceptance table matches the executable case catalog", async () => {
  const markdown = await readFile(guide, "utf8");
  const section = markdown.split("## Operator acceptance record\n")[1]?.split("\n### ")[0];
  assert.ok(section, "operator acceptance section must exist");
  const rows = [...section.matchAll(/^\| `([A-Z][0-9]{2})` \|/gmu)].map((match) => match[1]);
  assert.deepEqual(rows, ACCEPTANCE_CASES);
  assert.equal(new Set(rows).size, rows.length);
});

test("operator guide does not present fixture checks as deployed acceptance", async () => {
  const markdown = await readFile(guide, "utf8");
  assert.match(markdown, /simulator-backed actor journeys/u);
  assert.match(markdown, /not that\s+evidence/u);
  assert.match(markdown, /releaseQualified: false/u);
  assert.match(markdown, /does not independently authenticate finality/u);
});
