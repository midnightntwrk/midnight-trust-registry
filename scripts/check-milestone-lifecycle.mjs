#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = readFileSync(join(root, "packages/trust-registry-domain/src/lifecycle.ts"), "utf8");
const spec = readFileSync(join(root, "docs/spec/milestone-0.1.0.md"), "utf8");

const transitionBlock = source.match(/const lifecycleTransitionMap:[^=]+ = \{([\s\S]*?)\n\};/u)?.[1];
assert.ok(transitionBlock, "Cannot locate the domain lifecycle transition map");
const implemented = Object.fromEntries([...transitionBlock.matchAll(/^\s*(\w+): \[([^\]]*)\],\s*$/gmu)]
  .map(([, status, targets]) => [status, [...targets.matchAll(/"([^"]+)"/gu)].map((match) => match[1])]));
assert.ok(Object.keys(implemented).length > 0, "Domain lifecycle transition map is empty");

const documentedBlock = spec.match(/<!-- authorization-lifecycle-transitions:start -->([\s\S]*?)<!-- authorization-lifecycle-transitions:end -->/u)?.[1];
assert.ok(documentedBlock, "Cannot locate the milestone lifecycle transition table");
const documented = Object.fromEntries([...documentedBlock.matchAll(/^\| `(\w+)` \| ([^|]+) \|$/gmu)]
  .map(([, status, targets]) => [status, targets.trim() === "none" ? []
    : [...targets.matchAll(/`([^`]+)`/gu)].map((match) => match[1])]));
assert.deepEqual(documented, implemented, "Milestone lifecycle table differs from the domain validator");
assert.deepEqual(implemented.superseded, [], "The milestone profile must not claim a reachable superseded transition");

console.log("[check-milestone-lifecycle] Milestone states match the domain validator.");
