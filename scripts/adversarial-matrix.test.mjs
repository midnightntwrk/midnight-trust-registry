import assert from "node:assert/strict";
import { test } from "node:test";

import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import { runApplicationEvidenceSafetyScenarios } from "./governed-demo-application-evidence-safety.mjs";

test("runs signed application-evidence safety cases independently of the governed demo", () => {
  const matrix = new AdversarialMatrix();
  runApplicationEvidenceSafetyScenarios(matrix);
  assert.deepEqual(matrix.report().summary, { total: 2, passed: 2, failed: 0 });
  assert.deepEqual(matrix.report().cases.map(({ id }) => id), [
    "issuer-signed-wrong-policy-id",
    "issuer-expired-signed-application-evidence",
  ]);
});

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
  matrix.expectThrown(() => { throw new Error("Evidence commitment mismatch"); }, {
    id: "invalid-evidence-preflight",
    invariant: "Preflight must reject altered evidence before a simulator call",
    boundary: "integration",
    messagePattern: /commitment mismatch/iu,
    category: "evidence-commitment-rejected",
  });
  matrix.expectVerified(() => ({ trustedAtTime: true }), {
    id: "historical-issuer-trust",
    invariant: "Historical issuer trust survives later policy changes",
    boundary: "client",
  });
  assert.deepEqual(matrix.report(), {
    format: "tr-adversarial-matrix-v1",
    summary: { total: 5, passed: 5, failed: 0 },
    cases: [
      {
        id: "insufficient-quorum",
        invariant: "Governed action needs the configured quorum",
        boundary: "api",
        expected: "http:403/governed-action-rejected",
        observed: "http:403/governed-action-rejected",
        status: "passed",
      },
      {
        id: "wrong-registry",
        invariant: "Evidence must bind the selected registry",
        boundary: "client",
        expected: "registry-mismatch",
        observed: "matched:Error",
        status: "passed",
      },
      {
        id: "wrong-trqp-scope",
        invariant: "TRQP cannot project an unknown authorization scope",
        boundary: "adapter",
        expected: "trqp:404/not-found",
        observed: "trqp:404/not-found",
        status: "passed",
      },
      {
        id: "invalid-evidence-preflight",
        invariant: "Preflight must reject altered evidence before a simulator call",
        boundary: "integration",
        expected: "evidence-commitment-rejected",
        observed: "matched:Error",
        status: "passed",
      },
      {
        id: "historical-issuer-trust",
        invariant: "Historical issuer trust survives later policy changes",
        boundary: "client",
        expected: "accepted",
        observed: "accepted",
        status: "passed",
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

test("collects independent case failures without leaking response details", async () => {
  const matrix = new AdversarialMatrix({ collectFailures: true });
  await matrix.expectHttp({
    status: 503,
    json: async () => ({ type: "https://example.test/problems/internal-error", detail: "private data" }),
  }, {
    id: "first-failure", invariant: "The API must reject with the expected problem", boundary: "api",
    status: 403, problemType: "forbidden",
  });
  matrix.expectThrown(() => { throw new Error("private signer material"); }, {
    id: "second-failure", invariant: "The signer must be rejected", boundary: "compact",
    messagePattern: /inactive signer/u, category: "inactive-signer",
  });
  matrix.expectVerified(() => ({ trusted: true }), {
    id: "later-success", invariant: "A valid decision still runs", boundary: "client",
  });
  assert.deepEqual(matrix.report().summary, { total: 3, passed: 1, failed: 2 });
  assert.deepEqual(matrix.report().cases.map(({ id, status, reason }) => [id, status, reason]), [
    ["first-failure", "failed", "http-assertion-failed"],
    ["second-failure", "failed", "rejection-assertion-failed"],
    ["later-success", "passed", undefined],
  ]);
  assert.equal(JSON.stringify(matrix.report()).includes("private"), false);
  assert.throws(() => matrix.assertAllPassed(), /first-failure, second-failure/u);
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

test("records async rejections without leaking errors and rejects missing failures", async () => {
  const matrix = new AdversarialMatrix({ collectFailures: true });
  const expected = {
    invariant: "Recognition intake must reject invalid signed evidence",
    boundary: "integration",
    messagePattern: /signature is invalid/u,
    category: "recognition-signature-mismatch",
  };
  await matrix.expectRejected(async () => { throw new Error("signature is invalid for secret assertion"); }, {
    ...expected, id: "async-rejection",
  });
  await matrix.expectRejected(async () => {}, { ...expected, id: "async-missing-rejection" });
  assert.deepEqual(matrix.report().cases.map(({ id, status, reason }) => [id, status, reason]), [
    ["async-rejection", "passed", undefined],
    ["async-missing-rejection", "failed", "rejection-assertion-failed"],
  ]);
  assert.equal(JSON.stringify(matrix.report()).includes("secret"), false);
});

test("does not record a rejected historical verification", () => {
  const matrix = new AdversarialMatrix();
  assert.throws(() => matrix.expectVerified(() => { throw new Error("invalid proof"); }, {
    id: "historical-issuer-trust",
    invariant: "Historical issuer trust survives later policy changes",
    boundary: "client",
  }), /invalid proof/u);
  assert.deepEqual(matrix.report().cases, []);
});

test("records API and TRQP temporal decisions only when outcomes agree", () => {
  const matrix = new AdversarialMatrix();
  matrix.expectDecision({ trustedAtTime: false, statusAtTime: "suspended" }, {
    id: "issuer-suspended-api",
    invariant: "Suspended issuer trust must be denied",
    boundary: "api", trusted: false, statusAtTime: "suspended",
  });
  matrix.expectDecision({ authorized: false }, {
    id: "issuer-suspended-trqp",
    invariant: "TRQP must deny the same suspended issuer",
    boundary: "adapter", trusted: false,
  });
  assert.deepEqual(matrix.report().cases.map(({ expected, observed }) => [expected, observed]), [
    ["decision:deny/suspended", "decision:deny/suspended"],
    ["decision:deny", "decision:deny"],
  ]);
  assert.throws(() => matrix.expectDecision({ authorized: true }, {
    id: "issuer-wrong-trqp", invariant: "TRQP must agree", boundary: "adapter", trusted: false,
  }), /unexpected trust decision/u);
  assert.throws(() => matrix.expectDecision({ trustedAtTime: false, statusAtTime: "revoked" }, {
    id: "issuer-wrong-status", invariant: "Status must agree", boundary: "api",
    trusted: false, statusAtTime: "suspended",
  }), /unexpected lifecycle status/u);
  assert.equal(matrix.report().cases.length, 2);
});
