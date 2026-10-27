import assert from "node:assert/strict";
import { test } from "node:test";

import { pinnedStandaloneInventoryImages } from "./standalone-install-image-inventory-policy.mjs";

const images = ["node", "indexer", "proof-server"].map((role) => ({
  role,
  reference: `example.test/${role}@sha256:${"a".repeat(64)}`,
  archive: `images/${role}.tar`,
  archiveSha256: "b".repeat(64),
}));

test("accepts one digest-pinned archive for each required image role", () => {
  assert.deepEqual(pinnedStandaloneInventoryImages(images), images);
});

test("rejects missing, duplicate, malformed, and extra image roles", () => {
  for (const invalid of [null, {}, [], images.slice(0, 2),
    [images[0], images[1], images[1]],
    [images[0], images[1], { ...images[2], role: "api" }],
    [images[0], images[1], null]]) {
    assert.throws(() => pinnedStandaloneInventoryImages(invalid), /exactly once/u);
  }
});

test("rejects duplicate or missing archives and unpinned or malformed digests", () => {
  for (const changed of [
    { archive: images[0].archive }, { archive: null },
  ]) {
    assert.throws(() => pinnedStandaloneInventoryImages([images[0], images[1],
      { ...images[2], ...changed }]), /distinct pinned archive/u);
  }
  for (const changed of [
    { reference: "example.test/proof-server:latest" },
    { reference: null }, { archiveSha256: "g".repeat(64) }, { archiveSha256: null },
  ]) {
    assert.throws(() => pinnedStandaloneInventoryImages([images[0], images[1],
      { ...images[2], ...changed }]), /Unpinned or invalid container image: proof-server/u);
  }
});
