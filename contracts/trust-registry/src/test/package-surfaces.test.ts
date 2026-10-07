import { describe, expect, it } from "vitest";

import * as PackageSurface from "../index.js";

describe("trust registry contract package surfaces", () => {
  it("re-exports the managed contract, signing helpers, and simulator", () => {
    expect(PackageSurface.Contract).toBeDefined();
    expect(PackageSurface.pureCircuits).toBeDefined();
    expect(PackageSurface.TrustRegistryContract).toBeDefined();
    expect(PackageSurface.TrustRegistrySimulator).toBeDefined();
    expect(PackageSurface.signPolicyBoundMaintainerActionFromSeed).toBeDefined();
  });

  it("does not expose pre-release direct-create or unbound action APIs", () => {
    expect(PackageSurface).not.toHaveProperty("signMaintainerActionDigest");
    expect(PackageSurface).not.toHaveProperty("signMaintainerActionDigestFromSeed");
    expect(PackageSurface).not.toHaveProperty("verifyMaintainerActionDigest");
    expect(PackageSurface.pureCircuits).not.toHaveProperty("maintainerActionDigest");
    const simulator = new PackageSurface.TrustRegistrySimulator();
    expect(simulator).not.toHaveProperty("createVerifierAuthorization");
    expect(simulator).not.toHaveProperty("createAuditorAuthorization");
    expect(simulator).not.toHaveProperty("createRecognition");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createVerifierAuthorization");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createAuditorAuthorization");
    expect(simulator.contract.impureCircuits).not.toHaveProperty("createRecognition");
  });
});
