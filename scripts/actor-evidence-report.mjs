import assert from "node:assert/strict";

const roles = ["issuer", "verifier", "auditor", "recognition", "maintainer"];
const keyIdPattern = /^0x[0-9a-f]{64}$/u;
const caseIdPattern = /^[a-z][a-z0-9-]+$/u;

const belongsToRole = (caseId, role) =>
  caseId.split("-").includes(role);

/** Project only public decision evidence; never copy applicant or VP input into a report. */
export function buildActorEvidenceReport(entries, adversarialMatrix) {
  assert.equal(entries.length, roles.length, "Every governed actor must have one outcome");
  assert.equal(adversarialMatrix?.format, "tr-adversarial-matrix-v1");
  assert.ok(Array.isArray(adversarialMatrix.cases));
  const caseIds = new Set();
  for (const entry of adversarialMatrix.cases) {
    assert.match(entry.id, caseIdPattern);
    assert.equal(caseIds.has(entry.id), false, `Duplicate adversarial case: ${entry.id}`);
    caseIds.add(entry.id);
    assert.ok(typeof entry.expected === "string" && entry.expected.length > 0);
    assert.ok(typeof entry.observed === "string" && entry.observed.length > 0);
  }

  const byRole = new Map();
  for (const entry of entries) {
    assert.ok(roles.includes(entry.role), "Unknown governed actor role");
    assert.equal(byRole.has(entry.role), false, `Duplicate actor: ${entry.role}`);
    assert.match(entry.policyVersion, /^v[1-9][0-9]*$/u);
    assert.ok(typeof entry.epochId === "string" && entry.epochId.length > 0);
    assert.ok(["active-evidence", "membership-snapshot"].includes(entry.epochSource));
    assert.equal(entry.expectedResult, "active");
    assert.equal(entry.observedResult, entry.expectedResult, `${entry.role}: decision mismatch`);
    assert.ok(Array.isArray(entry.activationSignerKeyIds) && entry.activationSignerKeyIds.length >= 2);
    const signerKeyIds = entry.activationSignerKeyIds.map((keyId) => {
      assert.match(keyId, keyIdPattern);
      return keyId;
    });
    assert.equal(new Set(signerKeyIds).size, signerKeyIds.length, `${entry.role}: duplicate signer`);
    byRole.set(entry.role, {
      role: entry.role,
      policyVersion: entry.policyVersion,
      epochId: entry.epochId,
      epochSource: entry.epochSource,
      activationSignerKeyIds: signerKeyIds,
      expectedResult: entry.expectedResult,
      observedResult: entry.observedResult,
      rejectionCaseIds: adversarialMatrix.cases
        .filter((testCase) => belongsToRole(testCase.id, entry.role)
          && testCase.expected !== "accepted" && !testCase.expected.startsWith("decision:allow"))
        .map((testCase) => testCase.id),
    });
  }
  const actors = roles.map((role) => {
    const actor = byRole.get(role);
    assert.ok(actor, `Missing actor: ${role}`);
    assert.ok(actor.rejectionCaseIds.length > 0, `${role}: no rule-specific rejection was checked`);
    return actor;
  });
  return { format: "tr-actor-evidence-report-v1", actors };
}
