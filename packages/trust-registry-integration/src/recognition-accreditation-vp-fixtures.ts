import { Buffer } from "node:buffer";

import {
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKey, deriveJubjubPublicKeyFromSeed, encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import {
  RecognitionAccreditorAnchorSchema,
  RecognitionStatusAttestationSchema,
  canonicalizeJson,
  sha256Hex,
  type RecognitionAccreditationClaims,
  type RecognitionAccreditorAnchor,
} from "@midnight-ntwrk/trust-registry-domain";

import { encodeApplicationVpProof } from "./application-vp-proof-json.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "./did-resolution.js";
import { createMidnightDid } from "./fixtures.js";
import type { RecognitionStatusDecision } from "./recognition-accreditation-vp.js";
import { createAttestedRecognitionStatusSource, recognitionStatusAttestationDigest } from "./recognition-status-attestation.js";

export const RECOGNITION_VP_FIXTURE_TIME_MS = Date.parse("2026-05-20T00:10:00.000Z");
export const RECOGNITION_VP_FIXTURE_NONCE = `0x${"11".repeat(32)}`;
export const RECOGNITION_VP_FIXTURE_AUTHORITY_DID = createMidnightDid("accreditation-authority");
const accreditorDid = createMidnightDid("independent-accreditor");
const statusAuthorityDid = createMidnightDid("accreditation-status-authority");
const bytes32 = (value: string | Uint8Array): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

export const RECOGNITION_VP_FIXTURE_ANCHOR = RecognitionAccreditorAnchorSchema.parse({
  format: "tr-recognition-accreditor-anchor-v1",
  targetRegistryId: "registry:local:trusted",
  policyId: "policy:recognition:accreditors",
  policyVersion: "v1",
  accreditorDid,
  accreditorAssertionMethodId: `${accreditorDid}#assertion-1`,
  credentialFamilyId: "credential-family:registry-accreditation:v1",
  schemaId: "schema:registry-accreditation:v1",
  statusRegistryId: "status-registry:accreditation:v1",
  statusAuthorityDid,
  statusAuthorityMethodId: `${statusAuthorityDid}#assertion-1`,
  recognizedRegistryId: "registry:external:trusted",
  scopeResourceType: "credentialfamily",
  scopeResourceId: "credential-family:example:v1",
  effectiveFrom: "2026-05-20T00:00:00.000Z",
  effectiveUntil: "2026-05-21T00:00:00.000Z",
});

export async function createRecognitionAccreditationVpScenarioFixture(options: {
  nonce?: string;
  evaluatedAtMs?: number;
  authorityDid?: string;
  authorityAssertionSeed?: Uint8Array;
  anchor?: Partial<RecognitionAccreditorAnchor>;
  claims?: Partial<RecognitionAccreditationClaims>;
  presentationCredentialBodyRoot?: string;
  holderMethodId?: string;
  statusDecision?: Partial<RecognitionStatusDecision>;
  statusAttestation?: Record<string, unknown>;
} = {}) {
  const evaluatedAtMs = options.evaluatedAtMs ?? RECOGNITION_VP_FIXTURE_TIME_MS;
  const nonce = options.nonce ?? RECOGNITION_VP_FIXTURE_NONCE;
  const authorityDid = options.authorityDid ?? RECOGNITION_VP_FIXTURE_AUTHORITY_DID;
  const authorityAssertionSeed = options.authorityAssertionSeed ?? new Uint8Array(32).fill(31);
  const anchor = RecognitionAccreditorAnchorSchema.parse({
    ...RECOGNITION_VP_FIXTURE_ANCHOR,
    ...options.anchor,
  });
  const accreditorSecret = 19n;
  const holderSecret = 23n;
  const statusSeed = new Uint8Array(32).fill(29);
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(anchor.accreditorDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(accreditorSecret),
    }),
    createMidnightDidLedgerFixture(authorityDid, {
      schnorrJubjubAuthenticationMethods: [
        { id: "auth-1", publicKey: deriveJubjubPublicKey(holderSecret) },
      ],
      schnorrJubjubAssertionMethods: [
        { id: "assertion-1", publicKey: deriveJubjubPublicKeyFromSeed(authorityAssertionSeed) },
      ],
    }),
    createMidnightDidLedgerFixture(anchor.statusAuthorityDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(statusSeed),
    }),
  ]);
  const [accreditorMethod, holderMethod] = await Promise.all([
    resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(anchor.accreditorDid),
      verificationMethodId: anchor.accreditorAssertionMethodId,
      relationship: "assertionMethod",
    }),
    resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(authorityDid),
      verificationMethodId: "#auth-1",
      relationship: "authentication",
    }),
  ]);
  const claims: RecognitionAccreditationClaims = {
    version: "tr-recognition-accreditation-claims-v1",
    authorityDid,
    accreditorDid: anchor.accreditorDid,
    recognizedRegistryId: anchor.recognizedRegistryId,
    scopeResourceType: anchor.scopeResourceType,
    scopeResourceId: anchor.scopeResourceId,
    credentialFamilyId: anchor.credentialFamilyId,
    schemaId: anchor.schemaId,
    statusRegistryId: anchor.statusRegistryId,
    statusHandleCommitment: sha256Hex("accreditation-status-handle"),
    issuedAt: new Date(evaluatedAtMs - 60_000).toISOString(),
    expiresAt: new Date(evaluatedAtMs + 50 * 60_000).toISOString(),
    ...options.claims,
  };
  const rawCredentialBody = canonicalizeJson({
    version: "tr-recognition-accreditation-vp-body-v1",
    issuerMethodId: anchor.accreditorAssertionMethodId,
    holderMethodId: options.holderMethodId ?? `${authorityDid}#auth-1`,
    claims,
  });
  const credentialBodyRoot = bytes32(rawCredentialBody);
  const rawPresentationBody = canonicalizeJson({
    version: "tr-recognition-accreditation-presentation-v1",
    subjectDid: authorityDid,
    credentialBodyRoot: options.presentationCredentialBodyRoot ?? hex(credentialBodyRoot),
  });
  const presentationBodyRoot = bytes32(rawPresentationBody);
  const credentialProof = signMidnightDIDCredentialProof({
    methodBinding: accreditorMethod,
    secretScalar: accreditorSecret,
    bodyRoot: credentialBodyRoot,
    createdAt: BigInt(evaluatedAtMs - 60_000),
    challengeHash: bytes32("accreditation-issuance-challenge"),
  });
  const presentationProof = signMidnightDIDPresentationProof({
    methodBinding: holderMethod,
    secretScalar: holderSecret,
    bodyRoot: presentationBodyRoot,
    createdAt: BigInt(evaluatedAtMs),
    challengeHash: bytes32(Buffer.from(nonce.slice(2), "hex")),
  });
  const statusDidResult = await resolver.resolveResult(parseMidnightDIDString(anchor.statusAuthorityDid));
  const statusDidStateVersionId = statusDidResult?.didDocumentMetadata.versionId;
  if (typeof statusDidStateVersionId !== "string" || statusDidStateVersionId.length === 0) {
    throw new Error("Status authority fixture DID version is unavailable");
  }
  const statusDecision: RecognitionStatusDecision = {
    registryId: anchor.statusRegistryId,
    authorityMethodId: anchor.statusAuthorityMethodId,
    statusHandleCommitment: claims.statusHandleCommitment,
    active: true,
    validUntilMs: evaluatedAtMs + 15 * 60_000,
    decisionCommitment: sha256Hex("pinned-status-decision"),
    didStateVersionId: statusDidStateVersionId,
    ...options.statusDecision,
  };
  const statusStatement = RecognitionStatusAttestationSchema.parse({
    version: "tr-recognition-status-attestation-v1",
    targetRegistryId: anchor.targetRegistryId,
    statusRegistryId: anchor.statusRegistryId,
    statusAuthorityDid: anchor.statusAuthorityDid,
    statusAuthorityMethodId: anchor.statusAuthorityMethodId,
    statusHandleCommitment: claims.statusHandleCommitment,
    challengeHash: hex(bytes32(Buffer.from(nonce.slice(2), "hex"))),
    active: true,
    observedAt: new Date(evaluatedAtMs).toISOString(),
    expiresAt: new Date(evaluatedAtMs + 5 * 60_000).toISOString(),
    ...options.statusAttestation,
  });
  const signedStatusAttestation = {
    statement: statusStatement,
    proof: {
      verificationMethodId: anchor.statusAuthorityMethodId,
      algorithm: "jubjub-schnorr" as const,
      signature: hex(encodeJubjubSignature(signJubjubDigestFromSeed(
        statusSeed,
        recognitionStatusAttestationDigest(statusStatement, anchor.statusAuthorityMethodId),
      ))),
    },
  };
  const statusSource = options.statusDecision
    ? { verifyPinnedStatus: async () => statusDecision }
    : createAttestedRecognitionStatusSource({
      resolver,
      fetchAttestation: async () => signedStatusAttestation,
    });
  return {
    input: {
      submission: {
        rawCredentialBody,
        rawPresentationBody,
        credentialProof: encodeApplicationVpProof(credentialProof),
        presentationProof: encodeApplicationVpProof(presentationProof),
      },
      anchor,
      targetRegistryId: anchor.targetRegistryId,
      authorityDid,
      nonce,
      evaluatedAtMs,
      resolver,
      statusSource,
    },
    claims,
    statusSource,
    statusDecision,
    signedStatusAttestation,
    authorityAssertionSeed,
  };
}
