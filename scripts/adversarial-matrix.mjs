import assert from "node:assert/strict";

export class AdversarialMatrix {
  #cases = [];
  #ids = new Set();
  #collectFailures;

  constructor({ collectFailures = false } = {}) {
    this.#collectFailures = collectFailures;
  }

  #record(entry) {
    assert.match(entry.id, /^[a-z][a-z0-9-]+$/u);
    assert.ok(entry.invariant.length > 0);
    assert.ok(["compact", "integration", "client", "api", "adapter"].includes(entry.boundary));
    assert.equal(this.#ids.has(entry.id), false, `Duplicate adversarial case: ${entry.id}`);
    this.#ids.add(entry.id);
    this.#cases.push(entry);
  }

  #failure({ id, invariant, boundary }, expected, reason, error) {
    if (!this.#collectFailures) throw error;
    this.#record({ id, invariant, boundary, expected, observed: "failed", status: "failed", reason });
  }

  async expectHttp(response, { id, invariant, boundary, status, problemType }) {
    const expected = `http:${status}/${problemType}`;
    try {
      assert.equal(boundary, "api");
      assert.ok(Number.isInteger(status) && status >= 400 && status < 600);
      const payload = await response.json();
      assert.equal(response.status, status, JSON.stringify(payload));
      assert.equal(typeof payload.type, "string", "Rejected API response must have a problem type");
      const observedType = payload.type.slice(payload.type.lastIndexOf("/") + 1);
      assert.equal(observedType, problemType);
      this.#record({ id, invariant, boundary, expected, observed: `http:${response.status}/${observedType}`, status: "passed" });
      return payload;
    } catch (error) {
      return this.#failure({ id, invariant, boundary }, expected, "http-assertion-failed", error);
    }
  }

  expectAdapterProblem(result, { id, invariant, status, problemType }) {
    const expected = `trqp:${status}/${problemType}`;
    try {
      assert.equal(result.ok, false, "TRQP adapter must reject this case");
      const problem = result.problem;
      assert.equal(problem.status, status);
      assert.equal(typeof problem.type, "string");
      const observedType = problem.type.slice(problem.type.lastIndexOf("/") + 1);
      assert.equal(observedType, problemType);
      this.#record({ id, invariant, boundary: "adapter", expected,
        observed: `trqp:${problem.status}/${observedType}`, status: "passed" });
    } catch (error) {
      this.#failure({ id, invariant, boundary: "adapter" }, expected, "adapter-assertion-failed", error);
    }
  }

  expectDecision(decision, { id, invariant, boundary, trusted, statusAtTime, recognition = false }) {
    const category = `decision:${trusted ? "allow" : "deny"}${statusAtTime === undefined ? "" : `/${statusAtTime}`}`;
    try {
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
      this.#record({ id, invariant, boundary, expected: category, observed: category, status: "passed" });
    } catch (error) {
      this.#failure({ id, invariant, boundary }, category, "decision-assertion-failed", error);
    }
  }

  expectThrown(operation, { id, invariant, boundary, messagePattern, category }) {
    try {
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
      this.#record({ id, invariant, boundary, expected: category, observed: `matched:${failure.name}`, status: "passed" });
    } catch (error) {
      this.#failure({ id, invariant, boundary }, category, "rejection-assertion-failed", error);
    }
  }

  expectVerified(operation, { id, invariant, boundary }) {
    try {
      assert.ok(["integration", "client", "adapter"].includes(boundary));
      const value = operation();
      assert.ok(value, "Expected a verified result");
      this.#record({ id, invariant, boundary, expected: "accepted", observed: "accepted", status: "passed" });
      return value;
    } catch (error) {
      return this.#failure({ id, invariant, boundary }, "accepted", "verification-assertion-failed", error);
    }
  }

  report() {
    const failed = this.#cases.filter(({ status }) => status === "failed").length;
    return {
      format: "tr-adversarial-matrix-v1",
      summary: { total: this.#cases.length, passed: this.#cases.length - failed, failed },
      cases: this.#cases.map((entry) => ({ ...entry })),
    };
  }

  assertAllPassed() {
    const failed = this.#cases.filter(({ status }) => status === "failed");
    if (failed.length > 0) {
      throw new Error(`Adversarial cases failed: ${failed.map(({ id }) => id).join(", ")}`);
    }
  }
}
