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

function bootstrapMembership(harness) {
  return {
    maintainerIdCommitment: harness.maintainerIdCommitment,
    maintainerId: harness.maintainerId,
    subjectDidCommitment: harness.maintainerDidCommitment,
    keyId: harness.simulator.getLedger().lastAuthorizedMaintainerKeyId,
    seed: new Uint8Array(32),
    subjectDid: harness.maintainerDid,
    trustLevel: "bootstrap-maintainer",
  };
}

function runSelfVote(matrix, action) {
  const harness = new LocalTrustRegistryIntegrationHarness(`governed-demo-self-${action}`);
  const membership = bootstrapMembership(harness);
  const actionCount = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => {
    try {
      if (action === "suspend") harness.suspendMaintainer(membership);
      else harness.revokeMaintainer(membership);
    } finally {
      assert.equal(harness.simulator.getLedger().activeMaintainerCount, 1n);
      assert.equal(harness.simulator.getLedger().governanceActionCount, actionCount);
    }
  }, {
    id: `compact-self-voted-maintainer-${action === "suspend" ? "suspension" : "revocation"}`,
    invariant: `A maintainer cannot vote to ${action} its own DID`,
    boundary: "compact",
    messagePattern: /own DID/iu,
    category: "conflicted-maintainer-vote-rejected",
  });
}

function runThresholdRemoval(matrix, signCompact) {
  const harness = new LocalTrustRegistryIntegrationHarness("governed-demo-threshold-removal");
  const membership = bootstrapMembership(harness);
  const second = createMaintainerScenarioFixture("governed-demo-threshold-second");
  const third = createMaintainerScenarioFixture("governed-demo-threshold-third");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [second]);
  const removal = harness.prepareMaintainerDecisionAction(membership, "suspend");
  const actionCount = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => {
    try {
      harness.executeMaintainerDecisionWithSignatures(
        membership, "suspend", [signCompact(second, removal, harness)],
      );
    } finally {
      assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
      assert.equal(harness.simulator.getLedger().governanceActionCount, actionCount);
    }
  }, {
    id: "compact-removal-below-maintainer-threshold",
    invariant: "A non-conflicted signer cannot remove a maintainer into an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-threshold-protected",
  });
}

function runRemovedSigner(matrix, signCompact) {
  const harness = new LocalTrustRegistryIntegrationHarness("governed-demo-removed-signer");
  const removedSigner = createMaintainerScenarioFixture("governed-demo-removed-signer");
  const issuer = createIssuerScenarioFixture("governed-demo-removed-signer-issuer");
  harness.authorizeMaintainer(removedSigner);
  harness.suspendMaintainer(removedSigner);
  harness.proposeIssuer(issuer);
  const approval = harness.prepareIssuerDecisionAction(issuer, "approve");
  const actionCount = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => {
    try {
      harness.executeIssuerDecisionWithSignatures(
        issuer, "approve", [signCompact(removedSigner, approval, harness)],
      );
    } finally {
      assert.equal(harness.simulator.getLedger().governanceActionCount, actionCount);
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
export function runMaintainerSafetyCase(id, matrix, signCompact) {
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

export function runMaintainerSafetyScenarios(matrix, signCompact) {
  for (const id of maintainerSafetyCaseIds) runMaintainerSafetyCase(id, matrix, signCompact);
}
