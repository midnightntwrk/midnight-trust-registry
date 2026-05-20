import { describe, expect, it } from "vitest";

import * as PackageSurface from "../index.js";

describe("trust registry contract package surfaces", () => {
  it("re-exports the managed contract, signing helpers, and simulator", () => {
    expect(PackageSurface.Contract).toBeDefined();
    expect(PackageSurface.pureCircuits).toBeDefined();
    expect(PackageSurface.TrustRegistryContract).toBeDefined();
    expect(PackageSurface.TrustRegistrySimulator).toBeDefined();
    expect(PackageSurface.signMaintainerActionFromSeed).toBeDefined();
  });
});
