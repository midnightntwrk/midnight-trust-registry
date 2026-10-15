import { describe, expect, it } from "vitest";

import * as PackageSurface from "../index.js";
import { createMaintainerFixture, labelToBytes32, TrustRegistrySimulator } from "../testing.js";

describe("trust registry contract package surfaces", () => {
  it("re-exports the managed contract and signing helpers, but not testing fixtures", () => {
    expect(PackageSurface.Contract).toBeDefined();
    expect(PackageSurface.pureCircuits).toBeDefined();
    expect(PackageSurface.TrustRegistryContract).toBeDefined();
    expect(PackageSurface).not.toHaveProperty("TrustRegistrySimulator");
    expect(PackageSurface.signPolicyBoundMaintainerActionFromSeed).toBeDefined();
  });

  it("does not expose pre-release direct-create or unbound action APIs", () => {
    expect(PackageSurface).not.toHaveProperty("signMaintainerActionDigest");
    expect(PackageSurface).not.toHaveProperty("signMaintainerActionDigestFromSeed");
    expect(PackageSurface).not.toHaveProperty("verifyMaintainerActionDigest");
    expect(PackageSurface.pureCircuits).not.toHaveProperty("maintainerActionDigest");
    const maintainer = createMaintainerFixture("package-surface", 7);
    const simulator = new TrustRegistrySimulator({
      registryId: labelToBytes32("registry:package-surface"),
      networkIdCommitment: labelToBytes32("network:undeployed"),
      registryDidCommitment: labelToBytes32("did:midnight:package-surface"),
      governancePolicyCommitment: labelToBytes32("policy:package-surface"),
      maintainerId: maintainer.maintainerId,
      maintainerDidCommitment: maintainer.didCommitment,
      maintainerKeyId: maintainer.keyId,
      maintainerPublicKey: PackageSurface.deriveJubjubPublicKeyFromSeed(maintainer.seed),
      maintainerThreshold: 1n,
    });
    expect(simulator.contract.impureCircuits).not.toHaveProperty("initializeRegistry");
    expect(simulator).not.toHaveProperty("createVerifierAuthorization");
    expect(simulator).not.toHaveProperty("createAuditorAuthorization");
    expect(simulator).not.toHaveProperty("createRecognition");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createVerifierAuthorization");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createAuditorAuthorization");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createRecognition");
  });
});
