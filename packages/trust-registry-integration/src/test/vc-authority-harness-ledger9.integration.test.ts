import { describe, expect, it } from "vitest";
import { deriveJubjubPublicKeyFromSeed } from "@midnightntwrk/trust-registry-contract";
import { VcAuthorityKeyStatus } from "@midnightntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { bytes32Commitment, createMidnightDid } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 VC authority-key harness", () => {
  it("awaits governed registration and suspension in order", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("vc-authority-ledger9");
    const keyIdCommitment = bytes32Commitment("vc-authority:ledger9:key-1");
    const authorityDid = createMidnightDid("vc-authority-ledger9");
    const domain = {
      networkId: authorityDid.split(":")[2]!,
      consumerContractAddress: `0x${"a".repeat(64)}`,
      registryId: harness.registryId,
      registryContractAddress: `0x${harness.simulator.contractAddress}`,
      authorityDid,
      authorityMethodId: `${authorityDid}#authority-1`,
    };
    const publicKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(77));

    await expect(harness.registerVcAuthorityKey({ domain: { ...domain, registryId: "wrong" },
      keyIdCommitment, publicKey })).rejects.toThrow(/does not match the target registry/u);
    await harness.registerVcAuthorityKey({ domain, keyIdCommitment, publicKey });
    expect((await harness.simulator.getVcAuthorityKey(keyIdCommitment)).status).toBe(VcAuthorityKeyStatus.active);

    await harness.suspendVcAuthorityKey(keyIdCommitment, bytes32Commitment("vc-authority:ledger9:incident"));
    expect((await harness.simulator.getVcAuthorityKey(keyIdCommitment)).status).toBe(VcAuthorityKeyStatus.suspended);
  });
});
