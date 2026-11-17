import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it } from "vitest";

import { maintenanceSigningKeyHex, maintenanceVerifyingKeyHex } from "../maintenance-verifying-key.js";

describe("Ledger 9 maintenance key encoding", () => {
  it("encodes a Schnorr signing key and readback key identically", () => {
    const signingKey = sampleSigningKey();
    const verifyingKey = signatureVerifyingKey(signingKey);
    expect(maintenanceSigningKeyHex(signingKey)).toBe(maintenanceVerifyingKeyHex(verifyingKey));
    expect(maintenanceVerifyingKeyHex(verifyingKey)).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it("rejects non-Schnorr or malformed authority keys", () => {
    expect(() => maintenanceVerifyingKeyHex({ tag: "ed25519", value: "a".repeat(64) } as never)).toThrow(/Schnorr/);
    expect(() => maintenanceVerifyingKeyHex({ tag: "schnorr", value: "not-hex" } as never)).toThrow(/Schnorr/);
  });
});
