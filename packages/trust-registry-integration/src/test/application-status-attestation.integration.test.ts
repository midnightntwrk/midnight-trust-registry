import { Buffer } from "node:buffer";

import { signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import {
  applicationStatusAttestationDigest,
  applicationStatusDecisionCommitment,
  createAttestedApplicationStatusSource,
  type SignedApplicationStatusStatement,
} from "../application-status-attestation.js";
import { createApplicationVpScenarioFixture, VP_FIXTURE_NONCE, VP_FIXTURE_TIME_MS } from "../vp-scenario-fixtures.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

async function fixture() {
  const scenario = await createApplicationVpScenarioFixture();
  let signed: SignedApplicationStatusStatement = structuredClone(scenario.signedStatusAttestation);
  const source = createAttestedApplicationStatusSource({
    resolver: scenario.input.resolver,
    fetchAttestation: async () => signed,
  });
  const request = {
    material: scenario.material,
    binding: scenario.fixtureStatusPolicyBinding,
    nonce: VP_FIXTURE_NONCE,
    evaluatedAtMs: VP_FIXTURE_TIME_MS,
  };
  const replace = (statement: SignedApplicationStatusStatement["statement"], resign = true) => {
    signed = {
      statement,
      proof: {
        ...signed.proof,
        signature: resign
          ? hex(encodeJubjubSignature(signJubjubDigest(19n, applicationStatusAttestationDigest(statement))))
          : signed.proof.signature,
      },
    };
  };
  return { source, request, replace, signed, statement: signed.statement };
}

describe("DID-signed application status attestation", () => {
  it("binds the signed witness and resolved DID state version into the decision commitment", async () => {
    const { signed, statement } = await fixture();
    const original = applicationStatusDecisionCommitment(signed, "did-state-1");
    expect(applicationStatusDecisionCommitment(signed, "did-state-2")).not.toBe(original);
    expect(applicationStatusDecisionCommitment({
      ...signed,
      statement: { ...statement, observedAt: new Date(VP_FIXTURE_TIME_MS + 1000).toISOString() },
    }, "did-state-1")).not.toBe(original);
    expect(original).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it("accepts an active, fresh attestation pinned to the governed status anchor and credential", async () => {
    const { source, request } = await fixture();
    await expect(source(request)).resolves.toMatchObject({
      validUntilMs: VP_FIXTURE_TIME_MS + 5 * 60_000,
      statusDecisionCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
  });

  it.each([
    ["registry", { statusRegistryId: sha256Hex("other-registry") }],
    ["authority", { statusAuthorityMethodId: "did:midnight:other#assertion-1" }],
    ["handle", { statusHandleCommitment: sha256Hex("other-handle") }],
    ["credential root", { credentialBodyRoot: sha256Hex("other-credential") }],
    ["challenge", { challengeHash: sha256Hex("other-nonce") }],
    ["revocation", { active: false }],
  ])("rejects a re-signed %s substitution", async (_label, change) => {
    const { source, request, replace, statement } = await fixture();
    replace({ ...statement, ...change });
    await expect(source(request)).rejects.toThrow();
  });

  it("rejects a changed statement without a valid signature", async () => {
    const { source, request, replace, statement } = await fixture();
    replace({ ...statement, observedAt: new Date(VP_FIXTURE_TIME_MS + 1000).toISOString() }, false);
    await expect(source(request)).rejects.toThrow(/signature/u);
  });

  it.each([
    ["stale", { observedAt: new Date(VP_FIXTURE_TIME_MS - 6 * 60_000).toISOString() }],
    ["future", { observedAt: new Date(VP_FIXTURE_TIME_MS + 61_000).toISOString() }],
    ["expired", { expiresAt: new Date(VP_FIXTURE_TIME_MS - 1).toISOString() }],
    ["overlong", { expiresAt: new Date(VP_FIXTURE_TIME_MS + 6 * 60_000).toISOString() }],
  ])("rejects a %s re-signed observation", async (_label, change) => {
    const { source, request, replace, statement } = await fixture();
    replace({ ...statement, ...change });
    await expect(source(request)).rejects.toThrow(/current/u);
  });

  it("rejects a different intake nonce even for a valid attestation", async () => {
    const { source, request } = await fixture();
    await expect(source({ ...request, nonce: `0x${"22".repeat(32)}` })).rejects.toThrow();
  });

  it("rejects a credential-selected authority when the governed binding names another method", async () => {
    const { source, request } = await fixture();
    await expect(source({
      ...request,
      binding: {
        ...request.binding,
        statusAuthorityVerificationMethod: `${request.material.issuerDid}#other-method`,
      },
    })).rejects.toThrow();
  });
});
