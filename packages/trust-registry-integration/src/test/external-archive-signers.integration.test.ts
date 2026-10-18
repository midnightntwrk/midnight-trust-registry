import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createVerifierScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
} from "../local-simulator-harness.js";

type PreparedActionSigningContext = {
  registryId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
};

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  action: PreparedActionSigningContext,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    action.policyCommitment,
    action.actionKind,
    action.actionPayloadHash,
    action.actionSequence,
  ),
});

type ArchiveScenario = {
  prepare: () => PreparedActionSigningContext;
  execute: (signers: readonly MaintainerCoAuthorizer[]) => Uint8Array;
};

const scenarios = {
  issuer: (harness: LocalTrustRegistryIntegrationHarness): ArchiveScenario => {
    const fixture = createIssuerScenarioFixture("archive-issuer");
    harness.proposeIssuer(fixture);
    return {
      prepare: () => harness.prepareIssuerDecisionAction(fixture, "archive"),
      execute: (signers) => harness.executeIssuerDecisionWithSignatures(fixture, "archive", signers),
    };
  },
  verifier: (harness: LocalTrustRegistryIntegrationHarness): ArchiveScenario => {
    const fixture = createVerifierScenarioFixture("archive-verifier");
    harness.proposeVerifier(fixture);
    return {
      prepare: () => harness.prepareVerifierDecisionAction(fixture, "archive"),
      execute: (signers) => harness.executeVerifierDecisionWithSignatures(fixture, "archive", signers),
    };
  },
  auditor: (harness: LocalTrustRegistryIntegrationHarness): ArchiveScenario => {
    const fixture = createAuditorScenarioFixture("archive-auditor");
    harness.proposeAuditor(fixture);
    return {
      prepare: () => harness.prepareAuditorDecisionAction(fixture, "archive"),
      execute: (signers) => harness.executeAuditorDecisionWithSignatures(fixture, "archive", signers),
    };
  },
  maintainer: (harness: LocalTrustRegistryIntegrationHarness): ArchiveScenario => {
    const fixture = createMaintainerScenarioFixture("archive-maintainer");
    harness.proposeMaintainer(fixture);
    return {
      prepare: () => harness.prepareMaintainerDecisionAction(fixture, "archive"),
      execute: (signers) => harness.executeMaintainerDecisionWithSignatures(fixture, "archive", signers),
    };
  },
};

describe("externally signed proposal archival", () => {
  for (const [role, createScenario] of Object.entries(scenarios)) {
    it(`requires a fresh maintainer quorum to archive a proposed ${role}`, () => {
      const harness = new LocalTrustRegistryIntegrationHarness(`archive-${role}`);
      const second = createMaintainerScenarioFixture(`${role}-second`);
      const third = createMaintainerScenarioFixture(`${role}-third`);
      harness.authorizeMaintainer(second);
      harness.authorizeMaintainer(third);
      const scenario = createScenario(harness);
      harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

      const prepared = scenario.prepare();
      const signers = [signPrepared(harness, second, prepared), signPrepared(harness, third, prepared)];
      const before = harness.simulator.getLedger().governanceActionCount;
      expect(() => scenario.execute(signers.slice(0, 1))).toThrow();
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
      scenario.execute(signers);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
      expect(() => scenario.execute(signers)).toThrow();
    });
  }
});
