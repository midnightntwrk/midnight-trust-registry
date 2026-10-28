import assert from "node:assert/strict";
import { test } from "node:test";

import { exactFields } from "./standalone-exact-fields-policy.mjs";

test("requires precisely the expected signed-document fields", () => {
  assert.equal(exactFields({ a: 1, b: 2 }, ["b", "a"]), true);
  for (const value of [null, [], "a", { a: 1 }, { a: 1, b: 2, c: 3 }]) {
    assert.equal(exactFields(value, ["a", "b"]), false);
  }
});

test("rejects delimiter-containing field collisions and duplicate schemas", () => {
  assert.equal(exactFields({ "a\u0000b": 1 }, ["a", "b"]), false);
  assert.equal(exactFields({ a: 1 }, ["a", "a"]), false);
});
