import assert from "node:assert/strict";

export class AdversarialMatrix {
  #cases = [];
  #ids = new Set();

  #record(entry) {
    assert.match(entry.id, /^[a-z][a-z0-9-]+$/u);
    assert.ok(entry.invariant.length > 0);
    assert.ok(["compact", "client", "api", "adapter"].includes(entry.boundary));
    assert.equal(this.#ids.has(entry.id), false, `Duplicate adversarial case: ${entry.id}`);
    this.#ids.add(entry.id);
    this.#cases.push(entry);
  }

  async expectHttp(response, { id, invariant, boundary, status, problemType }) {
    assert.equal(boundary, "api");
    assert.ok(Number.isInteger(status) && status >= 400 && status < 600);
    const payload = await response.json();
    assert.equal(response.status, status, JSON.stringify(payload));
    assert.equal(typeof payload.type, "string", "Rejected API response must have a problem type");
    const observedType = payload.type.slice(payload.type.lastIndexOf("/") + 1);
    assert.equal(observedType, problemType);
    this.#record({ id, invariant, boundary, expected: `http:${status}/${problemType}`, observed: `http:${response.status}/${observedType}` });
    return payload;
  }

  expectThrown(operation, { id, invariant, boundary, messagePattern, category }) {
    assert.ok(boundary === "compact" || boundary === "client" || boundary === "adapter");
    assert.ok(messagePattern instanceof RegExp);
    assert.match(category, /^[a-z][a-z0-9-]+$/u);
    assert.throws(operation, messagePattern);
    this.#record({ id, invariant, boundary, expected: category, observed: category });
  }

  report() {
    return {
      format: "tr-adversarial-matrix-v1",
      cases: this.#cases.map((entry) => ({ ...entry })),
    };
  }
}
