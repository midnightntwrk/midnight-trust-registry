import assert from "node:assert/strict";
import { test } from "node:test";

import { exactFields, exactRecordFields, exactStringSet } from "./standalone-exact-fields-policy.mjs";

test("requires precisely the expected signed-document fields", () => {
  assert.equal(exactFields({ a: 1, b: 2 }, ["b", "a"]), true);
  for (const value of [null, [], "a", { a: 1 }, { a: 1, b: 2, c: 3 }]) {
    assert.equal(exactFields(value, ["a", "b"]), false);
  }
});

test("rejects delimiter-containing field collisions and duplicate schemas", () => {
  assert.equal(exactFields({ "a\u0000b": 1 }, ["a", "b"]), false);
  assert.equal(exactRecordFields({ "a\u0000b": 1 }, ["a", "b"]), false);
  assert.equal(exactFields({ "a|b": 1 }, ["a", "b"]), false);
  assert.equal(exactRecordFields({ a: 1, b: 2 }, ["a", "b"]), true);
  assert.equal(exactFields({ a: 1 }, ["a", "a"]), false);
});

test("rejects alternate delimiter partitions in name sets", () => {
  assert.equal(exactStringSet(["a", "b", "c"], ["c", "a", "b"]), true);
  assert.equal(exactStringSet(["a", "b\u0000c", "d"], ["a", "b", "c\u0000d"]), false);
  assert.equal(exactStringSet(["a", "a"], ["a", "b"]), false);
  assert.equal(exactStringSet(["a", 1], ["a", "b"]), false);
});
