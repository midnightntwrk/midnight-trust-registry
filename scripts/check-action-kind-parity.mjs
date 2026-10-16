import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const compact = readFileSync(new URL("../contracts/trust-registry/src/trust-registry.compact", import.meta.url), "utf8");
const governedKinds = [...compact.matchAll(
  /performAuthorizedMaintainerAction\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*pad\(\s*32\s*,\s*"(tr:[^"]+)"\s*\)/g,
)].map((match) => match[1]);
assert.equal(
  governedKinds.length,
  [...compact.matchAll(/performAuthorizedMaintainerAction\(/g)].length - 1,
  "Every Compact governed action must use a literal action kind",
);
assert.equal(new Set(governedKinds).size, governedKinds.length, "Compact governed action kinds must be distinct");

for (const path of [
  "../packages/trust-registry-integration/src/local-simulator-harness.ts",
  "../packages/trust-registry-client/src/evidence.ts",
]) {
  const source = readFileSync(new URL(path, import.meta.url), "utf8");
  const signerKinds = [...source.matchAll(/encodeCompactActionKind\(\s*"(tr:[^"]+)"\s*,?\s*\)/g)]
    .map((match) => match[1]);
  assert.ok(signerKinds.length > 0, `${path} has no signer action kinds`);
  assert.equal(
    signerKinds.length,
    [...source.matchAll(/encodeCompactActionKind\(/g)].length,
    `${path} has a signer action kind that is not a literal`,
  );
  for (const kind of signerKinds) {
    assert.ok(governedKinds.includes(kind), `${path} signs unknown Compact action kind ${kind}`);
  }
}

console.log("governed action kinds match Compact and shipping signer sources");
