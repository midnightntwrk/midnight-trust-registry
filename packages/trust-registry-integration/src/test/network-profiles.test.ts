import { describe, expect, it } from "vitest";

import {
  getLocalNetworkProfile,
  getNetworkProfile,
  TRUST_REGISTRY_NETWORK_PROFILES,
  validateNetworkProfiles,
} from "../network-profiles.js";

describe("versioned network profiles", () => {
  it("separates the local chain from all public networks without embedding a genesis pin", () => {
    expect(getLocalNetworkProfile()).toEqual({
      id: "standalone", networkId: "undeployed", kind: "self-hosted-local",
      genesisPinPolicy: "per-installation",
    });
    expect(TRUST_REGISTRY_NETWORK_PROFILES.map((profile) => profile.id)).toEqual([
      "standalone", "preview", "preprod", "mainnet",
    ]);
    for (const id of ["preview", "preprod", "mainnet"]) {
      expect(getNetworkProfile(id)).toEqual({
        id, networkId: id, kind: "public", genesisPinPolicy: "reviewed-network",
      });
    }
    expect(JSON.stringify(TRUST_REGISTRY_NETWORK_PROFILES)).not.toMatch(/genesisHash|secret|token|rpcUrl/u);
  });

  it("rejects unknown, duplicate, and cross-kind profile identities", () => {
    expect(() => getNetworkProfile("devnet")).toThrow(/Unknown Trust Registry network profile/u);
    const catalog = { format: "tr-network-profiles-v1", profiles: TRUST_REGISTRY_NETWORK_PROFILES };
    expect(() => validateNetworkProfiles({ ...catalog, profiles: [
      catalog.profiles[0], catalog.profiles[0], ...catalog.profiles.slice(2),
    ] })).toThrow(/unique IDs/u);
    expect(() => validateNetworkProfiles({ ...catalog, profiles: [
      { ...catalog.profiles[0], kind: "public" }, ...catalog.profiles.slice(1),
    ] })).toThrow(/identity or pin policy/u);
    expect(() => validateNetworkProfiles({ ...catalog, profiles: [
      catalog.profiles[0], { ...catalog.profiles[1], networkId: "mainnet" },
      ...catalog.profiles.slice(2),
    ] })).toThrow(/identity or pin policy/u);
    expect(() => validateNetworkProfiles({ ...catalog, profiles: [
      { ...catalog.profiles[0], expectedGenesisHash: `0x${"a".repeat(64)}` },
      ...catalog.profiles.slice(1),
    ] })).toThrow(/Invalid network profile/u);
  });
});
