import { describe, expect, it } from "vitest";

import { pureCircuits } from "../contract.js";
import {
  buildCanonicalMaintainerAuthorizationBundle,
  compareMaintainerKeyIds,
} from "../signing.js";

const signer = (keyId: Uint8Array) => ({
  keyId,
  publicKey: { x: 1n, y: 2n },
  signature: { announcement: { x: 3n, y: 4n }, response: 5n },
});

describe("canonical maintainer authorization bundles", () => {
  it("orders by Compact's little-endian key ID and pads without mutating input", () => {
    const low = new Uint8Array(32);
    low[0] = 1;
    const high = new Uint8Array(32);
    high[31] = 1;
    const input = [signer(high), signer(low)];
    const bundle = buildCanonicalMaintainerAuthorizationBundle(input);

    expect(compareMaintainerKeyIds(low, high)).toBeLessThan(0);
    expect(bundle.signerCount).toBe(2n);
    expect(bundle.signer1).toBe(input[1]);
    expect(bundle.signer2).toBe(input[0]);
    expect(input[0]!.keyId).toBe(high);
    expect(bundle.signer3.keyId).toEqual(new Uint8Array(32));
    expect(bundle.signer4.keyId).toEqual(new Uint8Array(32));
    expect(bundle.signer5.keyId).toEqual(new Uint8Array(32));
    expect(pureCircuits.maintainerSignerSetHash(
      bundle.signerCount,
      bundle.signer1.keyId,
      bundle.signer2.keyId,
      bundle.signer3.keyId,
      bundle.signer4.keyId,
      bundle.signer5.keyId,
    )).toEqual(pureCircuits.maintainerSignerSetHash(
      2n, low, high, new Uint8Array(32), new Uint8Array(32), new Uint8Array(32),
    ));
  });

  it("rejects empty, oversized, duplicate, and malformed signer sets", () => {
    const keyId = new Uint8Array(32).fill(1);
    expect(() => buildCanonicalMaintainerAuthorizationBundle([])).toThrow(/1 to 5/u);
    expect(() => buildCanonicalMaintainerAuthorizationBundle(Array.from({ length: 6 }, () => signer(keyId))))
      .toThrow(/1 to 5/u);
    expect(() => buildCanonicalMaintainerAuthorizationBundle([signer(keyId), signer(new Uint8Array(keyId))]))
      .toThrow(/duplicate key ID/u);
    expect(() => buildCanonicalMaintainerAuthorizationBundle([signer(new Uint8Array(31))]))
      .toThrow(/32 bytes/u);
    expect(() => buildCanonicalMaintainerAuthorizationBundle([signer(new Uint8Array(32))]))
      .toThrow(/nonzero/u);
  });
});
