import assert from "node:assert/strict";

export class AdversarialMatrix {
  #cases = [];
  #ids = new Set();

  #record(entry) {
    assert.match(entry.id, /^[a-z][a-z0-9-]+$/u);
    assert.ok(entry.invariant.length > 0);
    assert.ok(["compact", "integration", "client", "api", "adapter"].includes(entry.boundary));
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

  expectAdapterProblem(result, { id, invariant, status, problemType }) {
    assert.equal(result.ok, false, "TRQP adapter must reject this case");
    const problem = result.problem;
    assert.equal(problem.status, status);
    assert.equal(typeof problem.type, "string");
    const observedType = problem.type.slice(problem.type.lastIndexOf("/") + 1);
    assert.equal(observedType, problemType);
    this.#record({
      id,
      invariant,
      boundary: "adapter",
      expected: `trqp:${status}/${problemType}`,
      observed: `trqp:${problem.status}/${observedType}`,
    });
  }

  expectDecision(decision, { id, invariant, boundary, trusted, statusAtTime, recognition = false }) {
    assert.ok(["api", "adapter"].includes(boundary));
    assert.equal(typeof trusted, "boolean");
    assert.equal(recognition && boundary !== "adapter", false);
    const observed = boundary === "api" ? decision.trustedAtTime
      : recognition ? decision.recognized : decision.authorized;
    assert.equal(observed, trusted, `${id}: unexpected trust decision`);
    if (statusAtTime !== undefined) {
      assert.equal(boundary, "api");
      assert.equal(decision.statusAtTime, statusAtTime, `${id}: unexpected lifecycle status`);
    }
    const category = `decision:${trusted ? "allow" : "deny"}${statusAtTime === undefined ? "" : `/${statusAtTime}`}`;
    this.#record({ id, invariant, boundary, expected: category, observed: category });
  }

  expectThrown(operation, { id, invariant, boundary, messagePattern, category }) {
    assert.ok(["compact", "integration", "client", "adapter"].includes(boundary));
    assert.ok(messagePattern instanceof RegExp);
    assert.match(category, /^[a-z][a-z0-9-]+$/u);
    let failure;
    try {
      operation();
    } catch (error) {
      failure = error;
    }
    assert.ok(failure instanceof Error, "Expected an Error rejection");
    assert.match(failure.message, messagePattern);
    this.#record({
      id,
      invariant,
      boundary,
      expected: category,
      observed: `matched:${failure.name}`,
    });
  }

  expectVerified(operation, { id, invariant, boundary }) {
    assert.ok(["integration", "client", "adapter"].includes(boundary));
    const value = operation();
    assert.ok(value, "Expected a verified result");
    this.#record({ id, invariant, boundary, expected: "accepted", observed: "accepted" });
    return value;
  }

  report() {
    return {
      format: "tr-adversarial-matrix-v1",
      cases: this.#cases.map((entry) => ({ ...entry })),
    };
  }
}
