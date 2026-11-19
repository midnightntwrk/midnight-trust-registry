import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { pinnedStandaloneImages } from "./check-standalone-install.mjs";
import { pinnedStandaloneImagePolicy } from "./standalone-compose-image-policy.mjs";

const digest = "a".repeat(64);
const image = (role) => `example.test/${role}@sha256:${digest}`;
const services = Object.fromEntries(["node", "indexer", "proof-server"]
  .map((role) => [role, { image: image(role) }]));
const compose = { name: "${TR_STACK_NAME:-tr-standalone-ledger9-local}", services };

test("the checked-in Ledger 9 Compose images satisfy the install policy", async () => {
  const source = await readFile(new URL("../deploy/standalone/compose.yml", import.meta.url), "utf8");
  assert.deepEqual(pinnedStandaloneImages(source).map(({ role }) => role),
    ["node", "indexer", "proof-server"]);
});

test("accepts exactly the three digest-pinned standalone services", () => {
  const expected = ["node", "indexer", "proof-server"]
    .map((role) => ({ role, reference: image(role) }));
  assert.deepEqual(pinnedStandaloneImagePolicy(compose), expected);
  assert.deepEqual(pinnedStandaloneImages(`name: ${compose.name}\nservices:\n`
    + Object.entries(services).map(([role, service]) => `  ${role}:\n    image: ${service.image}\n`).join("")),
  expected);
});

test("rejects malformed service maps, extra roles, and unpinned references", () => {
  for (const invalid of [null, [], "compose", { ...compose, services: null },
    { ...compose, services: [] }, { ...compose, name: "other" },
    { ...compose, services: { ...services, api: { image: image("api") } } }]) {
    assert.throws(() => pinnedStandaloneImagePolicy(invalid), /dedicated project and exactly three services/u);
  }
  for (const invalidService of [null, [], "image", {}, { image: "example.test/node:latest" },
    { image: `example.test/node@sha256:${"g".repeat(64)}` }]) {
    assert.throws(() => pinnedStandaloneImagePolicy({ ...compose,
      services: { ...services, node: invalidService } }), /not digest pinned: node/u);
  }
});

test("rejects malformed YAML and a YAML sequence in place of services", () => {
  assert.throws(() => pinnedStandaloneImages("name: [\n"));
  assert.throws(() => pinnedStandaloneImages(`name: ${compose.name}\nservices: []\n`),
    /dedicated project and exactly three services/u);
});
