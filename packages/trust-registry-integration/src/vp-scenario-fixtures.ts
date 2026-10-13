import { Buffer } from "node:buffer";

import {
  createMidnightDIDHolderBinding,
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { deriveJubjubPublicKey, deriveJubjubPublicKeyFromSeed, signApplicationEvidenceCommitmentFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import { computeAuthorizationScopeCommitment, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

import { type ApplicationVpFamilyAdapter, type ApplicationVpMaterial } from "./application-vp-verifier.js";
import { decodeApplicationVpProof, encodeApplicationVpProof } from "./application-vp-proof-json.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "./did-resolution.js";
import { createIssuerAuthorizationScopeFixture, createIssuerScenarioFixture, createMidnightDid } from "./fixtures.js";

export const VP_FIXTURE_TIME_MS = Date.parse("2026-05-20T00:01:00.000Z");
export const VP_FIXTURE_NONCE = `0x${"11".repeat(32)}`;

const bytes32 = (value: string): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");

/** Local proof fixture with real published VC signatures but policy assertions supplied by a test family. */
export async function createApplicationVpScenarioFixture(
  nonce = VP_FIXTURE_NONCE,
  options: {
    subjectDid?: string;
    evidenceVerifierDid?: string;
    evidenceVerifierMethodId?: string;
    scopeCommitment?: string;
  } = {},
) {
  const issuerDid = createMidnightDid("vp-issuer");
  const subjectDid = options.subjectDid ?? createMidnightDid("vp-holder");
  const evidenceVerifierDid = options.evidenceVerifierDid ?? createMidnightDid("vp-evidence-verifier");
  const evidenceVerifierMethodId = options.evidenceVerifierMethodId ?? "assertion-1";
  const issuerSecret = 19n;
  const holderSecret = 23n;
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(issuerDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(issuerSecret),
    }),
    createMidnightDidLedgerFixture(subjectDid, {
      verificationMethodId: "auth-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(holderSecret),
    }),
    createMidnightDidLedgerFixture(evidenceVerifierDid, {
      verificationMethodId: evidenceVerifierMethodId,
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41)),
    }),
  ]);
  const issuerMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(issuerDid),
    verificationMethodId: "#assertion-1",
    relationship: "assertionMethod",
  });
  const holderMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(subjectDid),
    verificationMethodId: "#auth-1",
    relationship: "authentication",
  });
  const rawCredentialBody = "private-credential-body";
  const rawPresentationBody = "private-presentation-payload";
  const credentialBodyRoot = bytes32(rawCredentialBody);
  const presentationBodyRoot = bytes32(rawPresentationBody);
  const challengeHash = Buffer.from(sha256Hex(Buffer.from(nonce.slice(2), "hex")).slice(2), "hex");
  const holderBinding = createMidnightDIDHolderBinding(holderMethod).explicitBinding;
  const material: ApplicationVpMaterial = {
    issuerDid,
    issuerMethodId: "#assertion-1",
    subjectDid,
    holderMethodId: "#auth-1",
    credentialProof: signMidnightDIDCredentialProof({
      methodBinding: issuerMethod,
      secretScalar: issuerSecret,
      bodyRoot: credentialBodyRoot,
      createdAt: BigInt(VP_FIXTURE_TIME_MS - 60_000),
      challengeHash: bytes32("issuance-challenge"),
    }),
    presentationProof: signMidnightDIDPresentationProof({
      methodBinding: holderMethod,
      secretScalar: holderSecret,
      bodyRoot: presentationBodyRoot,
      createdAt: BigInt(VP_FIXTURE_TIME_MS),
      challengeHash,
    }),
    credentialBodyRoot,
    presentationBodyRoot,
    credentialHolderBinding: holderBinding,
    presentationHolderBinding: holderBinding,
    statusBinding: {
      registryRef: {
        registryId: bytes32("status-registry"),
        authorityVerificationMethodRef: issuerMethod.verificationMethodRef,
      },
      statusHandleCommitment: bytes32("credential-status-handle"),
    },
    credentialExpiresAtMs: VP_FIXTURE_TIME_MS + 60 * 60_000,
  };
  const scope = createIssuerAuthorizationScopeFixture(createIssuerScenarioFixture("vp"));
  const submission = {
    rawCredentialBody,
    rawPresentationBody,
    credentialProof: encodeApplicationVpProof(material.credentialProof),
    presentationProof: encodeApplicationVpProof(material.presentationProof),
  };
  const family: ApplicationVpFamilyAdapter<typeof submission> = {
    prepare: async (submitted) => {
      if (
        submitted === null || typeof submitted !== "object" || Array.isArray(submitted)
        || Object.keys(submitted).length !== 4
        || !Object.hasOwn(submitted, "rawCredentialBody")
        || !Object.hasOwn(submitted, "rawPresentationBody")
        || !Object.hasOwn(submitted, "credentialProof")
        || !Object.hasOwn(submitted, "presentationProof")
        || typeof submitted.rawCredentialBody !== "string"
        || typeof submitted.rawPresentationBody !== "string"
        || submitted.rawCredentialBody.length === 0 || submitted.rawCredentialBody.length > 16_384
        || submitted.rawPresentationBody.length === 0 || submitted.rawPresentationBody.length > 16_384
      ) throw new TypeError("Application VP fixture submission is invalid");
      return {
        ...material,
        credentialBodyRoot: bytes32(submitted.rawCredentialBody),
        presentationBodyRoot: bytes32(submitted.rawPresentationBody),
        credentialProof: decodeApplicationVpProof(submitted.credentialProof),
        presentationProof: decodeApplicationVpProof(submitted.presentationProof),
      };
    },
    assertCredentialBodyBinding: async () => true as const,
    assertIssuerEligible: async () => true as const,
    assertStatusActive: async () => ({ validUntilMs: VP_FIXTURE_TIME_MS + 15 * 60_000 }),
    assertRoleClaims: async () => ({
      claimsCommitment: sha256Hex("accepted-issuer-claims"),
      scopeCommitment: options.scopeCommitment ?? computeAuthorizationScopeCommitment(scope),
    }),
  };
  const verifierSeed = new Uint8Array(32).fill(41);
  const signer = {
    did: evidenceVerifierDid,
    keyId: `${evidenceVerifierDid}#${evidenceVerifierMethodId}`,
    publicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
    signCommitment: (keyId: Uint8Array, commitment: Uint8Array) =>
      signApplicationEvidenceCommitmentFromSeed(verifierSeed, keyId, commitment),
  };
  return {
    input: {
      submission,
      nonce,
      expectedSubjectDid: subjectDid,
      scope,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
      resolver,
      family,
    },
    material,
    family,
    signer,
  };
}
