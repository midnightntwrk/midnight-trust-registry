import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnightntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnightntwrk/trust-registry-contract";
import {
  createMaintainerFixture,
  type MaintainerCoAuthorizer,
} from "@midnightntwrk/trust-registry-contract/testing";

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
  "registryId" | "networkIdCommitment" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">;

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
    action.networkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"), action.policyCommitment,
    action.actionKind, action.actionPayloadHash, action.actionSequence,
  ),
});

describe("externally signed policy revision", () => {
  it("requires the old quorum to revise and the new quorum to register the verifier", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-policy-revision");
    const second = createMaintainerScenarioFixture("policy-second");
    const third = createMaintainerScenarioFixture("policy-third");
    const fourth = createMaintainerScenarioFixture("policy-fourth");
    const outsider = createMaintainerScenarioFixture("policy-outsider");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.authorizeMaintainer(fourth);
    await harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const revision = await harness.prepareThresholdPolicyRevisionAction(3n, 3n, 3n);
    const secondVote = signPrepared(harness, second, revision);
    const thirdVote = signPrepared(harness, third, revision);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    const executeRevision = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeThresholdPolicyRevisionWithSignatures(3n, 3n, 3n, signers);

    await expect(executeRevision([secondVote])).rejects.toThrow();
    await expect(executeRevision([secondVote, secondVote])).rejects.toThrow();
    await expect(executeRevision([secondVote, signPrepared(harness, outsider, revision)])).rejects.toThrow();
    await expect(executeRevision([
      signPrepared(harness, second, { ...revision, policyCommitment: new Uint8Array(32).fill(1) }), thirdVote,
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);

    await executeRevision([secondVote, thirdVote]);
    expect((await harness.simulator.getLedger()).maintainerThreshold).toBe(3n);
    expect(Uint8Array.from((await harness.simulator.getLedger()).governancePolicyCommitment))
      .toEqual(Uint8Array.from(revision.nextPolicyCommitment));
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 1n);
    await expect(executeRevision([secondVote, thirdVote])).rejects.toThrow();

    const issuer = createIssuerScenarioFixture("post-policy-issuer");
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 1n);
    await expect(harness.proposeIssuer(issuer, [second, third])).rejects.toThrow();

    const registration = await harness.prepareEvidenceVerifierRegistrationAction();
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const bootstrapVote = signPrepared(harness, bootstrap, registration);
    const secondRegistrationVote = signPrepared(harness, second, registration);
    const thirdRegistrationVote = signPrepared(harness, third, registration);
    const register = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeEvidenceVerifierRegistrationWithSignatures(signers);
    await expect(register([])).rejects.toThrow();
    await expect(register([signPrepared(harness, outsider, registration)])).rejects.toThrow();
    await expect(register([signPrepared(harness, bootstrap, revision)])).rejects.toThrow();
    await expect(register([bootstrapVote, secondRegistrationVote])).rejects.toThrow();
    await expect(register([bootstrapVote, bootstrapVote, thirdRegistrationVote])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 1n);

    expect(await register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).toHaveLength(32);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 2n);
    await expect(register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).rejects.toThrow();
    await expect(harness.proposeIssuer(issuer, [second])).rejects.toThrow();
    await harness.proposeIssuer(issuer, [second, third]);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 3n);
  }, 30_000);

  it("atomically recovers an active maintainer without exposing an intermediate low quorum", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("atomic-maintainer-recovery");
    const second = createMaintainerScenarioFixture("atomic-recovery-second");
    const target = createMaintainerScenarioFixture("atomic-recovery-target");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(target);
    await harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const before = await harness.simulator.getLedger();
    const evidenceHash = bytes32Commitment("incident:atomic-maintainer-recovery");
    const prepared = await harness.prepareAtomicMaintainerRecoveryAction(target, evidenceHash, 1n, 1n, 1n);
    const secondVote = signPrepared(harness, second, prepared);
    const targetVote = signPrepared(harness, target, prepared);
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const bootstrapVote = signPrepared(harness, bootstrap, prepared);
    const recover = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeAtomicMaintainerRecoveryWithSignatures(target, evidenceHash, 1n, 1n, 1n, signers);

    await expect(recover([bootstrapVote])).rejects.toThrow();
    await expect(recover([bootstrapVote, targetVote])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before.governanceActionCount);
    expect((await harness.simulator.getLedger()).governancePolicyCommitment)
      .toEqual(before.governancePolicyCommitment);
    expect((await harness.simulator.getMaintainerMembership(target.maintainerIdCommitment)).status)
      .toBe(AuthorizationStatus.active);

    const eventHash = await recover([bootstrapVote, secondVote]);
    const after = await harness.simulator.getLedger();
    expect(after.governanceActionCount).toBe(before.governanceActionCount + 1n);
    expect(after.activeMaintainerCount).toBe(2n);
    expect(after.maintainerThreshold).toBe(1n);
    expect(after.governancePolicyCommitment).toEqual(Uint8Array.from(prepared.nextPolicyCommitment));
    expect(harness.policyRecord.policyTemplates.find((template) => template.family === "maintainer")
      ?.applicableActionKinds).toContain("tr:maintainer:recover");
    expect(after.governancePolicyEffectiveFromByVersion.lookup(prepared.nextPolicyVersion))
      .toBe(before.governanceActionCount + 1n);
    expect((await harness.simulator.getMaintainerMembership(target.maintainerIdCommitment)).lifecycleEventHash)
      .toEqual(eventHash);
    await expect(recover([bootstrapVote, secondVote])).rejects.toThrow();
  }, 30_000);
});
