import assert from "node:assert/strict";
import { test } from "node:test";

import { assertSupersededUnreachable, parseLifecycleTransitions } from "./check-milestone-lifecycle.mjs";

const source = (entries) => `const lifecycleTransitionMap: Record<string, string[]> = {\n${entries}\n};`;

test("milestone lifecycle checker rejects inbound superseded transitions", () => {
  const valid = parseLifecycleTransitions(source('  active: ["archived"],\n  superseded: [],'));
  assert.doesNotThrow(() => assertSupersededUnreachable(valid));
  const invalid = parseLifecycleTransitions(source('  active: ["superseded"],\n  superseded: [],'));
  assert.throws(() => assertSupersededUnreachable(invalid), /must not make superseded reachable/u);
});

test("milestone lifecycle checker fails closed on skipped or malformed map entries", () => {
  for (const entries of [
    '  active: [\n    "archived",\n  ],\n  superseded: [],',
    '  active: ["archived"], // unparsed comment\n  superseded: [],',
    '  active: [archived],\n  superseded: [],',
    '  active: ["archived" "revoked"],\n  superseded: [],',
  ]) {
    assert.throws(() => parseLifecycleTransitions(source(entries)), /Cannot parse/u);
  }
  assert.throws(() => parseLifecycleTransitions(source('  active: [],\n  active: [],')),
    /duplicate states/u);
});
