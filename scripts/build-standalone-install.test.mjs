import assert from "node:assert/strict";
import { test } from "node:test";

import { pinnedStandaloneImages } from "./build-standalone-install.mjs";

const image = `midnightntwrk/test@sha256:${"a".repeat(64)}`;
const compose = `name: \${TR_STACK_NAME:-tr-standalone-local-smoke}
services:
  node: {image: ${image}}
  indexer: {image: ${image}}
  proof-server: {image: ${image}}
`;

test("accepts only three digest-pinned dedicated services", () => {
  assert.deepEqual(pinnedStandaloneImages(compose).map((entry) => entry.role),
    ["node", "indexer", "proof-server"]);
  assert.throws(() => pinnedStandaloneImages(compose.replace("sha256:", "latest-")), /digest pinned/u);
  assert.throws(() => pinnedStandaloneImages(`${compose}  extra: {image: ${image}}\n`), /exactly three/u);
  assert.throws(() => pinnedStandaloneImages(compose.replace("tr-standalone-local-smoke", "other")),
    /dedicated project/u);
  assert.throws(() => pinnedStandaloneImages(compose.replace("TR_STACK_NAME", "UNTRUSTED_PROJECT")),
    /dedicated project/u);
});
