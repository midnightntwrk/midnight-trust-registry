import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { prepareLocalIssuerWriterReview } from "./prepare-local-issuer-writer-review.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("prepares only private, unsigned, plan-bound issuer writer review bytes", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "tr-writer-review-"));
  const root = await realpath(temporary);
  try {
    const plan = {
      format: "tr-local-api-runtime-v3",
      sourceRevision: "a".repeat(40), installInventorySha256: "b".repeat(64),
      networkId: "undeployed", expectedGenesisHash: `0x${"c".repeat(64)}`,
      contractAddress: `0x${"d".repeat(64)}`,
      notBefore: new Date(Date.now() - 60_000).toISOString(),
      notAfter: new Date(Date.now() + 3_600_000).toISOString(),
    };
    const approved = { plan, planSha256: "e".repeat(64), reviewerFingerprint: "F".repeat(40) };
    const content = "1".repeat(64);
    const providerRoot = join(root, "installed-provider");
    const input = {
      outputDirectory: root, planPath: join(root, "plan.json"),
      signaturePath: join(root, "plan.sig"), keyringDirectory: join(root, "keyring"),
      reviewerFingerprint: approved.reviewerFingerprint, providerRoot,
      reviewedContentSha256: content, submissionJournalPath: join(root, "journal.json"),
    };
    const expected = { format: "tr-installed-provider-runtime-verification-v1",
      sourceRevision: plan.sourceRevision, installInventorySha256: plan.installInventorySha256,
      contentSha256: content, ownership: "trusted-tree-check-passed", releaseQualified: false };
    const calls = [];
    const dependencies = {
      loadPlan: async (options) => {
        calls.push(options);
        return approved;
      },
      verifyProvider: async (path, pins) => {
        assert.equal(path, providerRoot);
        assert.deepEqual(pins, { sourceRevision: plan.sourceRevision,
          inventorySha256: plan.installInventorySha256, contentSha256: content });
        return expected;
      },
    };
    const result = await prepareLocalIssuerWriterReview(input, dependencies);
    assert.equal(result.status, "unsigned-human-review-required");
    assert.equal(result.releaseQualified, false);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].requireApprovalChain, true);
    const bytes = await readFile(result.path);
    assert.equal(result.sha256, sha256(bytes));
    assert.equal((await stat(result.path)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(bytes.toString()), {
      format: "tr-local-issuer-writer-approval-v1",
      apiPlanSha256: approved.planSha256,
      reviewerFingerprint: approved.reviewerFingerprint,
      sourceRevision: plan.sourceRevision,
      installInventorySha256: plan.installInventorySha256,
      networkId: plan.networkId,
      expectedGenesisHash: plan.expectedGenesisHash,
      contractAddress: plan.contractAddress,
      providerRoot, providerContentSha256: content,
      submissionJournalPath: input.submissionJournalPath,
      notBefore: plan.notBefore, notAfter: plan.notAfter,
    });
    await assert.rejects(prepareLocalIssuerWriterReview(input, dependencies), { code: "EEXIST" });
    assert.equal(sha256(await readFile(result.path)), result.sha256);
    await assert.rejects(prepareLocalIssuerWriterReview({ ...input,
      submissionJournalPath: join(providerRoot, "journal.json") }, dependencies), /outside the provider tree/u);
    await assert.rejects(prepareLocalIssuerWriterReview({ ...input,
      outputDirectory: providerRoot }, dependencies), /outside the provider tree/u);
    await assert.rejects(prepareLocalIssuerWriterReview(input, {
      ...dependencies, verifyProvider: async () => ({ ...expected, contentSha256: "2".repeat(64) }),
    }), /report differs/u);
    await assert.rejects(prepareLocalIssuerWriterReview(input, {
      ...dependencies, loadPlan: async () => ({ ...approved, reviewerFingerprint: "A".repeat(40) }),
    }), /reviewer fingerprint/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
