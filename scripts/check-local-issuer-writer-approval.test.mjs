import assert from "node:assert/strict";
import test from "node:test";

import { checkLocalIssuerWriterApproval } from "./check-local-issuer-writer-approval.mjs";

const reviewerFingerprint = "A".repeat(40);
const planSha256 = "b".repeat(64);
const contentSha256 = "c".repeat(64);
const plan = {
  format: "tr-local-api-runtime-v3",
  sourceRevision: "d".repeat(40), installInventorySha256: "e".repeat(64),
  networkId: "undeployed", expectedGenesisHash: `0x${"1".repeat(64)}`,
  contractAddress: `0x${"2".repeat(64)}`,
};
const approval = {
  format: "tr-local-issuer-writer-approval-v1",
  apiPlanSha256: planSha256, reviewerFingerprint,
  sourceRevision: plan.sourceRevision, installInventorySha256: plan.installInventorySha256,
  networkId: plan.networkId, expectedGenesisHash: plan.expectedGenesisHash,
  contractAddress: plan.contractAddress, providerRoot: "/opt/trust-registry/provider",
  providerContentSha256: contentSha256,
  submissionJournalPath: "/var/lib/trust-registry/issuer-journal.json",
};
const input = { planPath: "/private/plan.json", planSignaturePath: "/private/plan.sig",
  writerApprovalPath: "/private/writer.json", writerSignaturePath: "/private/writer.sig",
  keyringDirectory: "/private/reviewer-keyring", reviewerFingerprint };

test("checks signed plan, writer annex, and installed provider without claiming actor finality", async () => {
  const calls = [];
  const dependencies = {
    loadPlan: async (received) => {
      assert.equal(received.requireApprovalChain, true);
      calls.push("plan");
      return { plan, planSha256, reviewerFingerprint };
    },
    loadWriter: async (received) => {
      assert.equal(received.planSha256, planSha256);
      assert.equal(received.approvedPlanReviewerFingerprint, reviewerFingerprint);
      calls.push("writer");
      return { approval, approvalSha256: "f".repeat(64) };
    },
    verifyProvider: async (root, pins) => {
      assert.equal(root, approval.providerRoot);
      assert.deepEqual(pins, { sourceRevision: plan.sourceRevision,
        inventorySha256: plan.installInventorySha256, contentSha256 });
      calls.push("provider");
      return { format: "tr-installed-provider-runtime-verification-v1",
        sourceRevision: plan.sourceRevision, installInventorySha256: plan.installInventorySha256,
        contentSha256, ownership: "trusted-tree-check-passed", releaseQualified: false };
    },
  };
  const result = await checkLocalIssuerWriterApproval(input, dependencies);
  assert.deepEqual(calls, ["plan", "writer", "provider"]);
  assert.equal(result.signedWriterApprovalVerified, true);
  assert.equal(result.installedProviderVerified, true);
  assert.equal(result.actorJourney, "not-run");
  assert.equal(result.independentFinality, "not-verified");
  assert.equal(result.releaseQualified, false);
  assert.equal(result.planSha256, planSha256);
  assert.equal(result.writerApprovalSha256, "f".repeat(64));

  await assert.rejects(checkLocalIssuerWriterApproval(input, {
    ...dependencies, loadPlan: async () => ({ plan, planSha256,
      reviewerFingerprint: "B".repeat(40) }),
  }), /verified v3 API plan reviewer/u);
  await assert.rejects(checkLocalIssuerWriterApproval(input, {
    ...dependencies, loadWriter: async () => ({ approval: { ...approval,
      contractAddress: `0x${"3".repeat(64)}` }, approvalSha256: "f".repeat(64) }),
  }), /differs from the approved API plan/u);
  await assert.rejects(checkLocalIssuerWriterApproval(input, {
    ...dependencies, verifyProvider: async () => ({
      format: "tr-installed-provider-runtime-verification-v1",
      sourceRevision: plan.sourceRevision, installInventorySha256: plan.installInventorySha256,
      contentSha256: "0".repeat(64), ownership: "trusted-tree-check-passed", releaseQualified: false,
    }),
  }), /provider differs from the signed writer annex/u);
});
