import assert from "node:assert/strict";

import { encodeJubjubSignature } from "../contracts/trust-registry/dist/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";

export async function runOtherGovernedProposals(matrix, {
  proposalTargets, base, harness, second, third, verifier, auditor, candidate,
  sign, signCompact, withAlteredProposalEvidence, assertValidProposalVerifierSignature,
  assertFreshProposalCanExecute, submitRawProposal, expectHttp, asHex,
}) {
  const otherProposals = [];
  for (const [role, target] of proposalTargets) {
    const evidence = target.evidence();
    assert.ok(evidence);
    const endpoint = `${base}/v1/governed/${role}/${target.id}/proposal`;
    const prepared = await expectHttp(await fetch(`${endpoint}/prepare`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ evidence }),
    }), 200);
    const compactPrepared = await target.prepare(evidence);
    const signature = await target.signEvidence(compactPrepared);
    const body = {
      evidence, prepared,
      signers: [await sign(second, prepared), await sign(third, prepared)],
      evidenceVerifierSignature: asHex(encodeJubjubSignature(signature)),
    };
    const submit = (payload) => fetch(`${endpoint}/submit`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    await matrix.expectHttp(await submit({ ...body, signers: body.signers.slice(0, 1) }), {
      id: `${role}-proposal-insufficient-quorum`,
      invariant: `A ${role} proposal requires the active maintainer quorum`,
      boundary: "api", status: 403, problemType: "governed-proposal-rejected",
    });
    await matrix.expectHttp(await submit({ ...body, signers: [body.signers[0], body.signers[0]] }), {
      id: `${role}-proposal-duplicate-signer`,
      invariant: `One maintainer cannot provide both signatures for a ${role} proposal quorum`,
      boundary: "api", status: 403, problemType: "invalid-governed-signature",
    });
    const compactSigner = await signCompact(second, compactPrepared);
    const compactCoSigner = await signCompact(third, compactPrepared);
    const beforeCompactQuorumRejections = (await harness.simulator.getLedger()).governanceActionCount;
    await matrix.expectRejected(() => target.execute(evidence, [compactSigner], signature), {
      id: `compact-${role}-proposal-insufficient-quorum`,
      invariant: `Compact requires the active maintainer quorum for a ${role} proposal`,
      boundary: "compact", messagePattern: /Maintainer signer count must satisfy the action threshold/u,
      category: "proposal-quorum-rejected",
    });
    await matrix.expectRejected(() => target.execute(evidence, [compactSigner, compactSigner], signature), {
      id: `client-${role}-proposal-duplicate-signer`,
      invariant: `The canonical bundle builder rejects a repeated ${role} proposal signer before Compact execution`,
      boundary: "client", messagePattern: /Maintainer authorization bundle contains a duplicate key ID/u,
      category: "proposal-duplicate-signer-rejected",
    });
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeCompactQuorumRejections);
    if (role === "verifier" || role === "auditor") {
      const fixture = role === "verifier" ? verifier : auditor;
      const alteredEvidenceHash = Uint8Array.from(compactPrepared.evidenceHash);
      alteredEvidenceHash[0] ^= 1;
      const beforeSubstitution = (await harness.simulator.getLedger()).governanceActionCount;
      const alteredPrepared = withAlteredProposalEvidence(role, fixture, compactPrepared, alteredEvidenceHash);
      const alteredVerifierSignature = await target.signEvidence(alteredPrepared);
      await assertValidProposalVerifierSignature(role, alteredPrepared, alteredVerifierSignature);
      await assertFreshProposalCanExecute(role, fixture, alteredPrepared, alteredVerifierSignature);
      await matrix.expectRejected(() => submitRawProposal(
        role, fixture, alteredPrepared, alteredVerifierSignature,
        [compactSigner, compactCoSigner],
      ), {
        id: `compact-${role}-proposal-altered-evidence-hash`,
        invariant: `A valid quorum cannot reuse its signed ${role} proposal with a substituted evidence commitment`,
        boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
        category: "proposal-evidence-substitution-rejected",
      });
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeSubstitution);
      const changedScope = role === "verifier"
        ? { ...fixture, allowedAttributeSetCommitment: bytes32Commitment("verifier:substituted-attributes") }
        : { ...fixture, requestResourceIdCommitment: bytes32Commitment("auditor:substituted-request") };
      const changedPrepared = withAlteredProposalEvidence(
        role, changedScope, compactPrepared, compactPrepared.evidenceHash,
      );
      const changedVerifierSignature = await target.signEvidence(changedPrepared);
      await assertValidProposalVerifierSignature(role, changedPrepared, changedVerifierSignature);
      await assertFreshProposalCanExecute(role, changedScope, changedPrepared, changedVerifierSignature);
      await matrix.expectRejected(() => submitRawProposal(
        role, changedScope, changedPrepared, changedVerifierSignature,
        [compactSigner, compactCoSigner],
      ), {
        id: `compact-${role}-proposal-scope-substitution`,
        invariant: `A ${role} proposal quorum cannot be reused for a changed request scope`,
        boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
        category: "proposal-scope-substitution-rejected",
      });
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeSubstitution);
    }
    if (role === "maintainer") {
      const alteredEvidenceHash = Uint8Array.from(compactPrepared.evidenceHash);
      alteredEvidenceHash[0] ^= 1;
      const beforeSubstitution = (await harness.simulator.getLedger()).governanceActionCount;
      const alteredPrepared = withAlteredProposalEvidence(role, candidate, compactPrepared, alteredEvidenceHash);
      const alteredVerifierSignature = await target.signEvidence(alteredPrepared);
      await assertValidProposalVerifierSignature(role, alteredPrepared, alteredVerifierSignature);
      await assertFreshProposalCanExecute(role, candidate, alteredPrepared, alteredVerifierSignature);
      await matrix.expectRejected(() => submitRawProposal(
        role, candidate, alteredPrepared, alteredVerifierSignature,
        [compactSigner, compactCoSigner],
      ), {
        id: "compact-maintainer-proposal-altered-evidence-hash",
        invariant: "A valid quorum cannot reuse its signed maintainer proposal with a substituted evidence commitment",
        boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
        category: "proposal-evidence-substitution-rejected",
      });
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeSubstitution);
    }
    assert.equal((await submit(body)).status, 202);
    const accepted = await expectHttp(await fetch(`${endpoint}/resolve`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ evidence }),
    }), 200);
    assert.equal(accepted.state, "observed");
    await expectHttp(await submit(body), 409);
    otherProposals.push({
      role, eventHash: accepted.eventHash, evidenceCommitment: evidence.commitment,
      source: "authenticated VP HTTP intake and governed HTTP proposal",
    });
  }
  return otherProposals;
}
