import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

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
    const outsider = createMaintainerScenarioFixture("policy-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const revision = harness.prepareThresholdPolicyRevisionAction(3n, 2n, 2n);
    const secondVote = signPrepared(harness, second, revision);
    const thirdVote = signPrepared(harness, third, revision);
    const before = harness.simulator.getLedger().governanceActionCount;
    const executeRevision = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeThresholdPolicyRevisionWithSignatures(3n, 2n, 2n, signers);

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
    expect(() => harness.proposeIssuer(issuer, [second, third])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);

    const registration = harness.prepareEvidenceVerifierRegistrationAction();
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const bootstrapVote = signPrepared(harness, bootstrap, registration);
    const secondRegistrationVote = signPrepared(harness, second, registration);
    const thirdRegistrationVote = signPrepared(harness, third, registration);
    const register = (signers: MaintainerCoAuthorizer[]) =>
      harness.executeEvidenceVerifierRegistrationWithSignatures(signers);
    expect(() => register([bootstrapVote, secondRegistrationVote])).toThrow();
    expect(() => register([bootstrapVote, secondRegistrationVote, secondRegistrationVote])).toThrow();
    expect(() => register([
      bootstrapVote, secondRegistrationVote, signPrepared(harness, outsider, registration),
    ])).toThrow();
    expect(() => register([
      signPrepared(harness, bootstrap, revision), secondRegistrationVote, thirdRegistrationVote,
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);

    expect(register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).toHaveLength(32);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 2n);
    expect(() => register([bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).toThrow();
    harness.proposeIssuer(issuer, [second, third]);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 3n);
  }, 30_000);
});
