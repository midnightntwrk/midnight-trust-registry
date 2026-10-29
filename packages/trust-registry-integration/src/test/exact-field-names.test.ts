import { describe, expect, it } from "vitest";

import { hasExactFieldNames } from "../exact-field-names.js";

describe("exact catalog field names", () => {
  it("rejects delimiter-collided names and duplicate schemas", () => {
    expect(hasExactFieldNames({ a: 1, b: 2 }, ["b", "a"])).toBe(true);
    expect(hasExactFieldNames({ "a\u0000b": 1 }, ["a", "b"])).toBe(false);
    expect(hasExactFieldNames({ a: 1 }, ["a", "a"])).toBe(false);
  });
});
