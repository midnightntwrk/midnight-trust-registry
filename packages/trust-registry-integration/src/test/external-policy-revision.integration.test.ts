import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  createMaintainerFixture,
  type MaintainerCoAuthorizer,
} from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedEvidenceVerifierRegistrationAction,
  type PreparedThresholdPolicyRevisionAction,
} from "../local-simulator-harness.js";

type PreparedAction = Pick<PreparedThresholdPolicyRevisionAction,
  "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">;

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: Pick<MaintainerScenarioFixture, "keyId" | "seed">,
  action: PreparedAction | PreparedEvidenceVerifierRegistrationAction,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"), action.policyCommitment,
    action.actionKind, action.actionPayloadHash, action.actionSequence,
  ),
});

describe("externally signed policy revision", () => {
  it("requires the old quorum to revise and the new quorum to register the verifier", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-policy-revision");
    const second = createMaintainerScenarioFixture("policy-second");
    const third = createMaintainerScenarioFixture("policy-third");
    const fourth = createMaintainerScenarioFixture("policy-fourth");
    const outsider = createMaintainerScenarioFixture("policy-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.authorizeMaintainer(fourth);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const revision = harness.prepareThresholdPolicyRevisionAction(3n, 3n, 3n);
    const secondVote = signPrepared(harness, second, revision);
    const thirdVote = signPrepared(harness, third, revision);
    const before = harness.simulator.getLedger().governanceActionCount;
    const executeRevision = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeThresholdPolicyRevisionWithSignatures(3n, 3n, 3n, signers);

    expect(() => executeRevision([secondVote])).toThrow();
    expect(() => executeRevision([secondVote, secondVote])).toThrow();
    expect(() => executeRevision([secondVote, signPrepared(harness, outsider, revision)])).toThrow();
    expect(() => executeRevision([
      signPrepared(harness, second, { ...revision, policyCommitment: new Uint8Array(32) }), thirdVote,
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

    executeRevision([secondVote, thirdVote]);
    expect(harness.simulator.getLedger().maintainerThreshold).toBe(3n);
    expect(Uint8Array.from(harness.simulator.getLedger().governancePolicyCommitment))
      .toEqual(Uint8Array.from(revision.nextPolicyCommitment));
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
    expect(() => executeRevision([secondVote, thirdVote])).toThrow();

    const issuer = createIssuerScenarioFixture("post-policy-issuer");
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
    expect(() => harness.proposeIssuer(issuer, [second, third])).toThrow();

    const registration = harness.prepareEvidenceVerifierRegistrationAction();
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const bootstrapVote = signPrepared(harness, bootstrap, registration);
    const secondRegistrationVote = signPrepared(harness, second, registration);
    const thirdRegistrationVote = signPrepared(harness, third, registration);
    const register = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeEvidenceVerifierRegistrationWithSignatures(signers);
    expect(() => register([])).toThrow();
    expect(() => register([signPrepared(harness, outsider, registration)])).toThrow();
    expect(() => register([signPrepared(harness, bootstrap, revision)])).toThrow();
    expect(() => register([bootstrapVote, secondRegistrationVote])).toThrow();
    expect(() => register([bootstrapVote, bootstrapVote, thirdRegistrationVote])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);

    expect(register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).toHaveLength(32);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 2n);
    expect(() => register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).toThrow();
    expect(() => harness.proposeIssuer(issuer, [second])).toThrow();
    harness.proposeIssuer(issuer, [second, third]);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 3n);
  }, 30_000);

  it("atomically recovers an active maintainer without exposing an intermediate low quorum", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("atomic-maintainer-recovery");
    const second = createMaintainerScenarioFixture("atomic-recovery-second");
    const target = createMaintainerScenarioFixture("atomic-recovery-target");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(target);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const before = harness.simulator.getLedger();
    const prepared = harness.prepareAtomicMaintainerRecoveryAction(target, 1n, 1n, 1n);
    const secondVote = signPrepared(harness, second, prepared);
    const targetVote = signPrepared(harness, target, prepared);
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const bootstrapVote = signPrepared(harness, bootstrap, prepared);
    const recover = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeAtomicMaintainerRecoveryWithSignatures(target, 1n, 1n, 1n, signers);

    expect(() => recover([bootstrapVote])).toThrow();
    expect(() => recover([bootstrapVote, targetVote])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before.governanceActionCount);
    expect(harness.simulator.getLedger().governancePolicyCommitment)
      .toEqual(before.governancePolicyCommitment);
    expect(harness.simulator.getMaintainerMembership(target.maintainerIdCommitment).status)
      .toBe(AuthorizationStatus.active);

    const eventHash = recover([bootstrapVote, secondVote]);
    const after = harness.simulator.getLedger();
    expect(after.governanceActionCount).toBe(before.governanceActionCount + 1n);
    expect(after.activeMaintainerCount).toBe(2n);
    expect(after.maintainerThreshold).toBe(1n);
    expect(after.governancePolicyCommitment).toEqual(Uint8Array.from(prepared.nextPolicyCommitment));
    expect(harness.policyRecord.policyTemplates.find((template) => template.family === "maintainer")
      ?.applicableActionKinds).toContain("tr:maintainer:recover");
    expect(after.governancePolicyEffectiveFromByVersion.lookup(prepared.nextPolicyVersion))
      .toBe(before.governanceActionCount + 1n);
    expect(harness.simulator.getMaintainerMembership(target.maintainerIdCommitment).lifecycleEventHash)
      .toEqual(eventHash);
    expect(() => recover([bootstrapVote, secondVote])).toThrow();
  }, 30_000);
});
