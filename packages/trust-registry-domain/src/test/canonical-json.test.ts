import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { canonicalizeJson, computeMutationPayloadCommitment } from "../canonical-json.js";

describe("canonical mutation payloads", () => {
  it("hashes exact validated payload semantics, not object insertion order", () => {
    const first = { target: "auditor", scope: { purpose: "KYC", credentialFamily: "identity" } };
    const reordered = { scope: { credentialFamily: "identity", purpose: "KYC" }, target: "auditor" };
    const expected = createHash("sha256").update(JSON.stringify([
      "tr:mutation:payload:v1",
      '{"scope":{"credentialFamily":"identity","purpose":"KYC"},"target":"auditor"}',
    ])).digest("hex");
    expect(computeMutationPayloadCommitment(first)).toBe(`0x${expected}`);
    expect(computeMutationPayloadCommitment(reordered)).toBe(`0x${expected}`);
    expect(computeMutationPayloadCommitment({ ...first, scope: { ...first.scope, purpose: "AML" } })).not.toBe(`0x${expected}`);
    expect(computeMutationPayloadCommitment({ ...first, target: "verifier" })).not.toBe(`0x${expected}`);
  });

  it("rejects non-JSON and non-finite values rather than omitting them", () => {
    const sparse = new Array<number>(3);
    sparse[0] = 1;
    sparse[2] = 2;
    for (const value of [undefined, { scope: undefined }, Number.NaN, Infinity, 1n]) {
      expect(() => canonicalizeJson(value)).toThrow(TypeError);
    }
    expect(() => canonicalizeJson(sparse)).toThrow(TypeError);
    expect(() => canonicalizeJson([1, undefined, 2])).toThrow(TypeError);
    expect(canonicalizeJson(["a", "b"])).not.toBe(canonicalizeJson(["b", "a"]));
  });
});
