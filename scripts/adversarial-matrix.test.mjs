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
  matrix.expectAdapterProblem({
    ok: false,
    problem: { type: "https://example.test/trqp/not-found", status: 404, detail: "private" },
  }, {
    id: "wrong-trqp-scope",
    invariant: "TRQP cannot project an unknown authorization scope",
    status: 404,
    problemType: "not-found",
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
        observed: "matched:Error",
      },
      {
        id: "wrong-trqp-scope",
        invariant: "TRQP cannot project an unknown authorization scope",
        boundary: "adapter",
        expected: "trqp:404/not-found",
        observed: "trqp:404/not-found",
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

test("does not record an unmatched or absent thrown rejection", () => {
  const matrix = new AdversarialMatrix();
  const expected = {
    id: "wrong-signer",
    invariant: "Only the active signer may approve",
    boundary: "compact",
    messagePattern: /active signer/iu,
    category: "inactive-signer",
  };
  assert.throws(() => matrix.expectThrown(() => { throw new Error("wrong policy"); }, expected));
  assert.throws(() => matrix.expectThrown(() => {}, expected));
  assert.deepEqual(matrix.report().cases, []);
});
