#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = readFileSync(join(root, "packages/trust-registry-domain/src/lifecycle.ts"), "utf8");
const spec = readFileSync(join(root, "docs/spec/milestone-0.1.0.md"), "utf8");

export function parseLifecycleTransitions(sourceText) {
  const transitionBlock = sourceText.match(/const lifecycleTransitionMap:[^=]+ = \{([\s\S]*?)\n\};/u)?.[1];
  assert.ok(transitionBlock, "Cannot locate the domain lifecycle transition map");
  const transitionLines = transitionBlock.split("\n").filter((line) => line.trim().length > 0);
  const parsedTransitions = [...transitionBlock.matchAll(/^\s*(\w+): \[([^\]]*)\],\s*$/gmu)];
  assert.equal(parsedTransitions.length, transitionLines.length,
    "Cannot parse every domain lifecycle transition entry");
  const implemented = Object.fromEntries(parsedTransitions.map(([, status, targets]) => {
    let targetNames;
    try {
      targetNames = JSON.parse(`[${targets}]`);
    } catch {
      throw new Error(`Cannot parse ${status} targets`);
    }
    assert.ok(targetNames.every((target) => typeof target === "string" && /^\w+$/u.test(target)),
      `Cannot parse ${status} targets`);
    return [status, targetNames];
  }));
  assert.ok(Object.keys(implemented).length > 0, "Domain lifecycle transition map is empty");
  assert.equal(Object.keys(implemented).length, parsedTransitions.length,
    "Domain lifecycle transition map contains duplicate states");
  return implemented;
}

export function assertSupersededUnreachable(implemented) {
  assert.deepEqual(implemented.superseded, [], "The milestone profile must not claim a transition out of superseded");
  assert.ok(Object.values(implemented).every((targets) => !targets.includes("superseded")),
    "The milestone profile must not make superseded reachable");
}

const implemented = parseLifecycleTransitions(source);

const documentedBlock = spec.match(/<!-- authorization-lifecycle-transitions:start -->([\s\S]*?)<!-- authorization-lifecycle-transitions:end -->/u)?.[1];
assert.ok(documentedBlock, "Cannot locate the milestone lifecycle transition table");
const documented = Object.fromEntries([...documentedBlock.matchAll(/^\| `(\w+)` \| ([^|]+) \|$/gmu)]
  .map(([, status, targets]) => [status, targets.trim() === "none" ? []
    : [...targets.matchAll(/`([^`]+)`/gu)].map((match) => match[1])]));
assert.deepEqual(documented, implemented, "Milestone lifecycle table differs from the domain validator");
assertSupersededUnreachable(implemented);

console.log("[check-milestone-lifecycle] Milestone states match the domain validator.");
