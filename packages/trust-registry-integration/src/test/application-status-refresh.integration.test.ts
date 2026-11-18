import { Buffer } from "node:buffer";

import { signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import {
  applicationStatusAttestationDigest,
  type SignedApplicationStatusStatement,
} from "../application-status-attestation.js";
import { verifyApplicationVp } from "../application-vp-verifier.js";
import { refreshCapturedApplicationStatus } from "../application-status-refresh.js";
import {
  createApplicationVpScenarioFixture,
  VP_FIXTURE_TIME_MS,
} from "../vp-scenario-fixtures.js";

const freshNonce = `0x${"42".repeat(32)}`;
const challengeHash = (nonce: string): string => sha256Hex(Buffer.from(nonce.slice(2), "hex"));

async function fixture() {
  const scenario = await createApplicationVpScenarioFixture();
  const verified = await verifyApplicationVp(scenario.input);
  const original = scenario.readStatusWitness(challengeHash(scenario.input.nonce));
  if (original === null) throw new Error("Fixture status witness is missing");
  const signedFresh = (active: boolean): SignedApplicationStatusStatement => {
    const statement = {
      ...original.statement,
      challengeHash: challengeHash(freshNonce),
      active,
      observedAt: new Date(VP_FIXTURE_TIME_MS + 1000).toISOString(),
      expiresAt: new Date(VP_FIXTURE_TIME_MS + 5 * 60_000 + 1000).toISOString(),
    };
    return {
      statement,
      proof: {
        ...original.proof,
        signature: `0x${Buffer.from(encodeJubjubSignature(signJubjubDigest(
          19n, applicationStatusAttestationDigest(statement),
        ))).toString("hex")}`,
      },
    };
  };
  const fetchFreshAttestation = vi.fn(async () => signedFresh(true));
  const input = {
    acceptedEnvelope: {
      challengeHash: challengeHash(scenario.input.nonce),
      statusDecisionCommitment: verified.statusDecisionCommitment,
      verifiedAt: verified.verifiedAt,
      expiresAt: verified.expiresAt,
    },
    witness: {
      signed: original,
      nonce: scenario.input.nonce,
      material: {
        credentialBodyRoot: scenario.material.credentialBodyRoot,
        statusBinding: scenario.material.statusBinding,
      },
    },
    binding: scenario.fixtureStatusPolicyBinding,
    resolver: scenario.input.resolver,
    fetchFreshAttestation,
    freshNonce,
    trustedTimeMs: VP_FIXTURE_TIME_MS + 1000,
  };
  return { input, fetchFreshAttestation, signedFresh };
}

describe("private application status refresh", () => {
  it("verifies the accepted witness before a fresh signed authority decision", async () => {
    const { input, fetchFreshAttestation } = await fixture();
    const result = await refreshCapturedApplicationStatus(input);
    expect(result).toEqual({
      validUntilMs: Date.parse(input.acceptedEnvelope.expiresAt),
      statusDecisionCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
    expect(JSON.stringify(result)).not.toContain("privateStatusWitness");
    expect(fetchFreshAttestation).toHaveBeenCalledExactlyOnceWith({
      statusRegistryId: input.binding.statusRegistryId,
      statusHandleCommitment: input.witness.signed.statement.statusHandleCommitment,
      credentialBodyRoot: input.witness.signed.statement.credentialBodyRoot,
      challengeHash: challengeHash(freshNonce),
    });
  });

  it("does not query live status for a witness from another accepted challenge", async () => {
    const { input, fetchFreshAttestation } = await fixture();
    await expect(refreshCapturedApplicationStatus({
      ...input,
      acceptedEnvelope: { ...input.acceptedEnvelope, challengeHash: sha256Hex("another-challenge") },
    })).rejects.toThrow(/accepted challenge/u);
    expect(fetchFreshAttestation).not.toHaveBeenCalled();
  });

  it("does not query live status when the original decision or governed binding differs", async () => {
    const { input, fetchFreshAttestation } = await fixture();
    await expect(refreshCapturedApplicationStatus({
      ...input,
      acceptedEnvelope: {
        ...input.acceptedEnvelope, statusDecisionCommitment: sha256Hex("other-status-decision"),
      },
    })).rejects.toThrow(/private witness/u);
    await expect(refreshCapturedApplicationStatus({
      ...input,
      binding: { ...input.binding, statusPolicyContentCommitment: sha256Hex("other-policy") },
    })).rejects.toThrow(/private witness/u);
    expect(fetchFreshAttestation).not.toHaveBeenCalled();
  });

  it("rejects expired evidence, reused nonce, and a newly revoked status", async () => {
    const { input, fetchFreshAttestation, signedFresh } = await fixture();
    await expect(refreshCapturedApplicationStatus({
      ...input, trustedTimeMs: Date.parse(input.acceptedEnvelope.expiresAt),
    })).rejects.toThrow(/not current/u);
    await expect(refreshCapturedApplicationStatus({
      ...input, freshNonce: input.witness.nonce,
    })).rejects.toThrow(/context is invalid/u);
    expect(fetchFreshAttestation).not.toHaveBeenCalled();
    fetchFreshAttestation.mockResolvedValueOnce(signedFresh(false));
    await expect(refreshCapturedApplicationStatus(input)).rejects.toThrow(/not active/u);
  });
});
