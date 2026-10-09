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
    for (const value of [undefined, { scope: undefined }, Number.NaN, Infinity, 1n,
      new Date("2026-10-10T00:00:00Z"), new Map([["a", 1]]), new Set([1]),
      { nested: new Date("2026-10-10T00:00:00Z") }]) {
      expect(() => canonicalizeJson(value)).toThrow(TypeError);
    }
    expect(() => canonicalizeJson(sparse)).toThrow(TypeError);
    expect(() => canonicalizeJson([1, undefined, 2])).toThrow(TypeError);
    expect(canonicalizeJson(["a", "b"])).not.toBe(canonicalizeJson(["b", "a"]));
  });

  it("rejects cycles and ambiguous object properties without evaluating accessors", () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    const arrayCycle: unknown[] = [];
    arrayCycle.push(arrayCycle);
    expect(() => canonicalizeJson(cycle)).toThrow(TypeError);
    expect(() => canonicalizeJson(arrayCycle)).toThrow(TypeError);

    const symbolProperty = { value: 1, [Symbol("extra")]: 2 };
    expect(() => canonicalizeJson(symbolProperty)).toThrow(TypeError);

    const hiddenProperty = { value: 1 };
    Object.defineProperty(hiddenProperty, "hidden", { value: 2 });
    expect(() => canonicalizeJson(hiddenProperty)).toThrow(TypeError);

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "value", {
      enumerable: true,
      get: () => { getterCalls += 1; return 1; },
    });
    expect(() => canonicalizeJson(accessor)).toThrow(TypeError);
    expect(getterCalls).toBe(0);

    const extraArrayProperty = Object.assign([1], { extra: 2 });
    expect(() => canonicalizeJson(extraArrayProperty)).toThrow(TypeError);
    const accessorArray = [1];
    Object.defineProperty(accessorArray, "0", { get: () => { getterCalls += 1; return 1; } });
    expect(() => canonicalizeJson(accessorArray)).toThrow(TypeError);
    expect(getterCalls).toBe(0);

    const shared = { value: 1 };
    expect(canonicalizeJson({ left: shared, right: shared })).toBe(
      '{"left":{"value":1},"right":{"value":1}}',
    );
  });
});
