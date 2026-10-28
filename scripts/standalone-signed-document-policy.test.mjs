import assert from "node:assert/strict";
import { test } from "node:test";

import { exactFields, parseCanonicalSignedJson } from "./standalone-signed-document-policy.mjs";

test("accepts only the two signed JSON byte encodings", () => {
  const value = { a: 1, b: "approved" };
  assert.deepEqual(parseCanonicalSignedJson(Buffer.from(JSON.stringify(value)), "Approval"), value);
  assert.deepEqual(parseCanonicalSignedJson(Buffer.from(`${JSON.stringify(value, null, 2)}\n`), "Approval"), value);
});

test("rejects duplicate keys, noncanonical whitespace, malformed UTF-8, and invalid JSON", () => {
  for (const bytes of [
    Buffer.from('{"a":1,"a":2}'),
    Buffer.from('{ "a": 1 }'),
    Buffer.from('{"a":1}\n'),
    Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
    Buffer.from("{"),
  ]) {
    assert.throws(() => parseCanonicalSignedJson(bytes, "Approval"));
  }
});

test("exact field shape rejects missing, extra, and non-record values", () => {
  assert.equal(exactFields({ a: 1, b: 2 }, ["b", "a"]), true);
  for (const value of [null, [], "a", { a: 1 }, { a: 1, b: 2, c: 3 }]) {
    assert.equal(exactFields(value, ["a", "b"]), false);
  }
});
