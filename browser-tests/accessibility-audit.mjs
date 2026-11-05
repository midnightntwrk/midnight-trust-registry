import AxeBuilder from "@axe-core/playwright";

import { expect } from "./offline-browser-fixture.mjs";

export async function expectNoWcagViolations(page, view) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  const failures = results.violations.map(({ id, impact, nodes }) => ({
    id, impact, targets: nodes.map(({ target }) => target),
  }));
  expect(failures, view).toEqual([]);
}
