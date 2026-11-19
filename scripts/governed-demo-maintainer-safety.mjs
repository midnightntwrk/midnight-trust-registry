import assert from "node:assert/strict";

import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

export const maintainerSafetyCaseIds = Object.freeze([
  "compact-self-voted-maintainer-suspension",
  "compact-self-voted-maintainer-revocation",
  "compact-removal-below-maintainer-threshold",
  "compact-removed-maintainer-signer",
]);

async function bootstrapMembership(harness) {
  return {
    maintainerIdCommitment: harness.maintainerIdCommitment,
    maintainerId: harness.maintainerId,
    subjectDidCommitment: harness.maintainerDidCommitment,
    keyId: (await harness.simulator.getLedger()).lastAuthorizedMaintainerKeyId,
    seed: new Uint8Array(32),
    subjectDid: harness.maintainerDid,
    trustLevel: "bootstrap-maintainer",
  };
}

async function runSelfVote(matrix, action) {
  const harness = new LocalTrustRegistryIntegrationHarness(`governed-demo-self-${action}`);
  await harness.ready;
  const membership = await bootstrapMembership(harness);
  const actionCount = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => {
    try {
      if (action === "suspend") await harness.suspendMaintainer(membership);
      else await harness.revokeMaintainer(membership);
    } finally {
      assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 1n);
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, actionCount);
    }
  }, {
    id: `compact-self-voted-maintainer-${action === "suspend" ? "suspension" : "revocation"}`,
    invariant: `A maintainer cannot vote to ${action} its own DID`,
    boundary: "compact",
    messagePattern: /own DID/iu,
    category: "conflicted-maintainer-vote-rejected",
  });
}

async function runThresholdRemoval(matrix, signCompact) {
  const harness = new LocalTrustRegistryIntegrationHarness("governed-demo-threshold-removal");
  const membership = await bootstrapMembership(harness);
  const second = createMaintainerScenarioFixture("governed-demo-threshold-second");
  const third = createMaintainerScenarioFixture("governed-demo-threshold-third");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [second]);
  const removal = await harness.prepareMaintainerDecisionAction(membership, "suspend");
  const actionCount = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => {
    try {
      await harness.executeMaintainerDecisionWithSignatures(
        membership, "suspend", [await signCompact(second, removal, harness)],
      );
    } finally {
      assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 3n);
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, actionCount);
    }
  }, {
    id: "compact-removal-below-maintainer-threshold",
    invariant: "A non-conflicted signer cannot remove a maintainer into an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-threshold-protected",
  });
}

async function runRemovedSigner(matrix, signCompact) {
  const harness = new LocalTrustRegistryIntegrationHarness("governed-demo-removed-signer");
  const removedSigner = createMaintainerScenarioFixture("governed-demo-removed-signer");
  const issuer = createIssuerScenarioFixture("governed-demo-removed-signer-issuer");
  await harness.authorizeMaintainer(removedSigner);
  await harness.suspendMaintainer(removedSigner);
  await harness.proposeIssuer(issuer);
  const approval = await harness.prepareIssuerDecisionAction(issuer, "approve");
  const actionCount = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => {
    try {
      await harness.executeIssuerDecisionWithSignatures(
        issuer, "approve", [await signCompact(removedSigner, approval, harness)],
      );
    } finally {
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, actionCount);
    }
  }, {
    id: "compact-removed-maintainer-signer",
    invariant: "A suspended maintainer key cannot approve a new issuer",
    boundary: "compact",
    messagePattern: /active|authorized|maintainer|signature|assert/iu,
    category: "removed-signer-rejected",
  });
}

/** Each fixture owns its own simulator; this does not exercise a deployed ledger. */
export async function runMaintainerSafetyCase(id, matrix, signCompact) {
  switch (id) {
    case "compact-self-voted-maintainer-suspension":
      return runSelfVote(matrix, "suspend");
    case "compact-self-voted-maintainer-revocation":
      return runSelfVote(matrix, "revoke");
    case "compact-removal-below-maintainer-threshold":
      return runThresholdRemoval(matrix, signCompact);
    case "compact-removed-maintainer-signer":
      return runRemovedSigner(matrix, signCompact);
    default:
      throw new Error(`Unknown maintainer safety case: ${id}`);
  }
}

export async function runMaintainerSafetyScenarios(matrix, signCompact) {
  for (const id of maintainerSafetyCaseIds) await runMaintainerSafetyCase(id, matrix, signCompact);
}
