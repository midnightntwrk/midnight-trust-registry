import assert from "node:assert/strict";
import { test } from "node:test";

import { AdversarialMatrix } from "./adversarial-matrix.mjs";

test("records checked problem types and scrubbed client rejection categories", async () => {
  const matrix = new AdversarialMatrix();
  await matrix.expectHttp({
    status: 403,
    json: async () => ({ type: "https://example.test/problems/governed-action-rejected", detail: "secret" }),
  }, {
    id: "insufficient-quorum",
    invariant: "Governed action needs the configured quorum",
    boundary: "api",
    status: 403,
    problemType: "governed-action-rejected",
  });
  matrix.expectThrown(() => { throw new Error("Registry mismatch for private value"); }, {
    id: "wrong-registry",
    invariant: "Evidence must bind the selected registry",
    boundary: "client",
    messagePattern: /registry mismatch/iu,
    category: "registry-mismatch",
  });
  assert.deepEqual(matrix.report(), {
    format: "tr-adversarial-matrix-v1",
    cases: [
      {
        id: "insufficient-quorum",
        invariant: "Governed action needs the configured quorum",
        boundary: "api",
        expected: "http:403/governed-action-rejected",
        observed: "http:403/governed-action-rejected",
      },
      {
        id: "wrong-registry",
        invariant: "Evidence must bind the selected registry",
        boundary: "client",
        expected: "registry-mismatch",
        observed: "registry-mismatch",
      },
    ],
  });
  assert.equal(JSON.stringify(matrix.report()).includes("secret"), false);
  assert.throws(() => matrix.expectThrown(() => { throw new Error("again"); }, {
    id: "wrong-registry",
    invariant: "Evidence must bind the selected registry",
    boundary: "client",
    messagePattern: /again/u,
    category: "registry-mismatch",
  }), /Duplicate adversarial case/u);
});

test("fails closed when an API changes its rejection category", async () => {
  const matrix = new AdversarialMatrix();
  await assert.rejects(matrix.expectHttp({
    status: 403,
    json: async () => ({ type: "https://example.test/problems/internal-error" }),
  }, {
    id: "insufficient-quorum",
    invariant: "Governed action needs the configured quorum",
    boundary: "api",
    status: 403,
    problemType: "governed-action-rejected",
  }));
  assert.deepEqual(matrix.report().cases, []);
});
