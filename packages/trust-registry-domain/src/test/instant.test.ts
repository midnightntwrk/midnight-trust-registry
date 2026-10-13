import { describe, expect, it } from "vitest";

import { compareRfc3339Instants } from "../instant.js";

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
});
