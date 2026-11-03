import { describe, expect, it } from "vitest";

import { assertIssuerEvidenceCurrentAtTrustedTime } from "../local-issuer-proposal-port.js";

describe("local issuer evidence trusted-time boundary", () => {
  it("rejects a trusted millisecond just before fractional verification time", () => {
    const envelope = {
      verifiedAt: "2026-07-27T14:00:00.0000000001+02:00",
      expiresAt: "2026-07-27T12:00:00.002Z",
    };
    const base = Date.parse("2026-07-27T12:00:00.000Z");
    expect(() => assertIssuerEvidenceCurrentAtTrustedTime(envelope, base))
      .toThrow(/not current at trusted time/u);
    expect(() => assertIssuerEvidenceCurrentAtTrustedTime(envelope, base + 1)).not.toThrow();
    expect(() => assertIssuerEvidenceCurrentAtTrustedTime(envelope, base + 2))
      .toThrow(/not current at trusted time/u);
  });

  it("rejects timestamps outside the supported Date range", () => {
    const envelope = { verifiedAt: "2026-07-27T12:00:00Z", expiresAt: "2026-07-27T13:00:00Z" };
    expect(() => assertIssuerEvidenceCurrentAtTrustedTime(envelope, Number.MAX_SAFE_INTEGER))
      .toThrow(/invalid value/u);
  });
});
