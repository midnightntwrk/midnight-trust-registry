import { describe, expect, it } from "vitest";

import { compareRfc3339Instants, isRfc3339DurationWithinSeconds } from "../instant.js";

describe("RFC3339 instant comparison", () => {
  it("preserves sub-millisecond ordering", () => {
    expect(compareRfc3339Instants("2026-05-20T00:00:00.000001Z", "2026-05-20T00:00:00.000Z")).toBe(1);
    expect(compareRfc3339Instants("2026-05-20T00:00:00.0000001Z", "2026-05-20T00:00:00.000001Z")).toBe(-1);
  });

  it("treats equivalent offsets and zero-padded fractions as one instant", () => {
    expect(compareRfc3339Instants("2026-05-20T00:00:00.100Z", "2026-05-20T02:00:00.1000+02:00")).toBe(0);
  });

  it("rejects malformed input", () => {
    expect(() => compareRfc3339Instants("bad", "2026-05-20T00:00:00Z")).toThrow(/invalid timestamp/);
  });

  it("bounds a whole-second duration without dropping fractional digits", () => {
    const start = "2026-05-20T02:00:00.0000000001+02:00";
    expect(isRfc3339DurationWithinSeconds(start, "2026-05-21T00:00:00.0000000001Z", 86_400)).toBe(true);
    expect(isRfc3339DurationWithinSeconds(start, "2026-05-21T00:00:00.0000000002Z", 86_400)).toBe(false);
    expect(isRfc3339DurationWithinSeconds(start, "2026-05-20T23:59:59.9999999999Z", 86_400)).toBe(true);
    expect(isRfc3339DurationWithinSeconds(start, "2026-05-20T00:00:00Z", 86_400)).toBe(false);
    expect(() => isRfc3339DurationWithinSeconds(start, start, Number.MAX_SAFE_INTEGER))
      .toThrow(/maximumSeconds/u);
  });
});
