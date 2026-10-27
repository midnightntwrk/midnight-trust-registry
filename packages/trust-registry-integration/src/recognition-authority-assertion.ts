import { Buffer } from "node:buffer";

import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import type { JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  HashHexSchema,
  RecognitionAuthorityAssertionSchema,
  SignedRecognitionAuthorityAssertionSchema,
  compareRfc3339Instants,
  recognitionAuthorityEvidenceCommitment,
  recognitionAuthorityStatementCommitment,
  sha256Hex,
  type RecognitionAuthorityAssertion,
  type SignedRecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyDidJubjubSignature } from "./did-signature-verification.js";

const MAX_FUTURE_SKEW_MS = 60_000;

const digestField = (value: string): bigint =>
  BigInt(`0x${sha256Hex(value).slice(2, 64)}`);

/** Four bounded fields avoid interpreting an arbitrary SHA-256 value as a Compact field. */
export const recognitionAuthorityAssertionDigest = (
  statement: RecognitionAuthorityAssertion,
  verificationMethodId: string,
): JubjubDigest => [
  digestField("tr:recognition:authority-signature:v1"),
  digestField(statement.targetRegistryId),
  digestField(verificationMethodId),
  digestField(recognitionAuthorityStatementCommitment(statement)),
];

export type RecognitionAuthorityAssertionExpectation = {
  targetRegistryId: string;
  recognitionId: string;
  authorityDid: string;
  recognizedRegistryId: string;
  scopeResourceType: string;
  scopeResourceId: string;
  challengeHash: string;
  evaluatedAtMs: number;
};

export type VerifiedRecognitionAuthorityAssertion = {
  statement: RecognitionAuthorityAssertion;
  evidenceCommitment: string;
  verificationMethodId: string;
  didStateVersionId: string;
  evaluatedAtMs: number;
};

/** Verifies DID control and statement integrity, not the referenced accreditation's validity. */
export async function verifyRecognitionAuthorityAssertion(input: {
  signed: SignedRecognitionAuthorityAssertion;
  expected: RecognitionAuthorityAssertionExpectation;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
}): Promise<VerifiedRecognitionAuthorityAssertion> {
  const signed = SignedRecognitionAuthorityAssertionSchema.parse(input.signed);
  const expected = input.expected;
  const statement = RecognitionAuthorityAssertionSchema.parse(signed.statement);
  const methodId = signed.proof.verificationMethodId;
  if (!Number.isSafeInteger(expected.evaluatedAtMs) || expected.evaluatedAtMs < 0) {
    throw new Error("Recognition assertion evaluation time is invalid");
  }
  if (!Number.isFinite(new Date(expected.evaluatedAtMs + MAX_FUTURE_SKEW_MS).getTime())) {
    throw new Error("Recognition assertion evaluation time is outside the supported range");
  }
  const challengeHash = HashHexSchema.parse(expected.challengeHash).toLowerCase();
  if (
    statement.targetRegistryId !== expected.targetRegistryId
    || statement.recognitionId !== expected.recognitionId
    || statement.authorityDid !== expected.authorityDid
    || statement.recognizedRegistryId !== expected.recognizedRegistryId
    || statement.scopeResourceType !== expected.scopeResourceType
    || statement.scopeResourceId !== expected.scopeResourceId
    || statement.challengeHash.toLowerCase() !== challengeHash
    || !methodId.startsWith(`${statement.authorityDid}#`)
  ) {
    throw new Error("Recognition authority assertion does not match the requested tuple");
  }
  const evaluatedAt = new Date(expected.evaluatedAtMs).toISOString();
  const latestIssuedAt = new Date(expected.evaluatedAtMs + MAX_FUTURE_SKEW_MS).toISOString();
  if (compareRfc3339Instants(statement.issuedAt, latestIssuedAt) > 0
    || compareRfc3339Instants(statement.expiresAt, evaluatedAt) <= 0) {
    throw new Error("Recognition authority assertion is not current");
  }
  let didStateVersionId: string | undefined;
  const observedResolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
    resolveResult: async (did) => {
      const result = await input.resolver.resolveResult(did);
      if (result?.didDocument.id === statement.authorityDid) {
        const versionId = result.didDocumentMetadata.versionId;
        if (typeof versionId === "string") didStateVersionId = versionId;
      }
      return result;
    },
  };
  const method = await resolveMidnightDIDMethodBinding({
    resolver: observedResolver,
    did: parseMidnightDIDString(statement.authorityDid),
    verificationMethodId: methodId,
    relationship: "assertionMethod",
  });
  if (!verifyDidJubjubSignature(
    method.publicKey,
    recognitionAuthorityAssertionDigest(statement, methodId),
    signed.proof.signature,
  )) {
    throw new Error("Recognition authority assertion signature is invalid");
  }
  if (didStateVersionId === undefined || didStateVersionId.length === 0) {
    throw new Error("Recognition authority DID state version is unavailable");
  }
  return {
    statement,
    evidenceCommitment: sha256Hex(JSON.stringify([
      "tr:recognition:verified-authority-evidence:v1",
      recognitionAuthorityEvidenceCommitment(signed),
      didStateVersionId,
      expected.evaluatedAtMs,
    ])),
    verificationMethodId: methodId,
    didStateVersionId,
    evaluatedAtMs: expected.evaluatedAtMs,
  };
}

export const recognitionAuthorityEvidenceBytes = (
  verified: VerifiedRecognitionAuthorityAssertion,
): Uint8Array => Buffer.from(verified.evidenceCommitment.slice(2), "hex");
