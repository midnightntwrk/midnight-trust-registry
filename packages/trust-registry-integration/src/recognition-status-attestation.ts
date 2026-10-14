import { Buffer } from "node:buffer";

import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import { verifyJubjubDigest, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex } from "@midnight-ntwrk/trust-registry-contract";
import {
  SignedRecognitionStatusAttestationSchema,
  recognitionStatusAttestationCommitment,
  recognitionStatusStatementCommitment,
  sha256Hex,
  type RecognitionStatusAttestation,
  type RecognitionAccreditorAnchor,
  type SignedRecognitionStatusAttestation,
} from "@midnight-ntwrk/trust-registry-domain";

import type { RecognitionAccreditationStatusSource, RecognitionStatusDecision } from "./recognition-accreditation-vp.js";

const MAX_AGE_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 60_000;
const NONCE_HEX = /^0x[0-9a-f]{64}$/u;
const field = (value: string): bigint => BigInt(`0x${sha256Hex(value).slice(2, 64)}`);

export const recognitionStatusAttestationDigest = (
  statement: RecognitionStatusAttestation,
  methodId: string,
): JubjubDigest => [
  field("tr:recognition:status-signature:v1"),
  field(statement.targetRegistryId),
  field(methodId),
  field(recognitionStatusStatementCommitment(statement)),
];

/** A fetcher supplies bytes, but only the policy-pinned DID assertion key authorizes their content. */
export function createAttestedRecognitionStatusSource(input: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  fetchAttestation: (request: {
    anchor: RecognitionAccreditorAnchor;
    statusHandleCommitment: string;
    challengeHash: string;
  }) => Promise<unknown>;
}): RecognitionAccreditationStatusSource {
  return {
    async verifyPinnedStatus(request): Promise<RecognitionStatusDecision> {
      if (!NONCE_HEX.test(request.nonce)
        || !Number.isSafeInteger(request.evaluatedAtMs)
        || request.evaluatedAtMs < 0) {
        throw new Error("Recognition status request context is invalid");
      }
      const challengeHash = sha256Hex(Buffer.from(request.nonce.slice(2), "hex"));
      const signed: SignedRecognitionStatusAttestation = SignedRecognitionStatusAttestationSchema.parse(
        await input.fetchAttestation({
          anchor: request.anchor,
          statusHandleCommitment: request.statusHandleCommitment,
          challengeHash,
        }),
      );
      const statement = signed.statement;
      if (statement.targetRegistryId !== request.anchor.targetRegistryId
        || statement.statusRegistryId !== request.anchor.statusRegistryId
        || statement.statusAuthorityDid !== request.anchor.statusAuthorityDid
        || statement.statusAuthorityMethodId !== request.anchor.statusAuthorityMethodId
        || statement.statusHandleCommitment !== request.statusHandleCommitment
        || statement.challengeHash !== challengeHash
        || signed.proof.verificationMethodId !== request.anchor.statusAuthorityMethodId) {
        throw new Error("Recognition status attestation does not match the pinned request");
      }
      const observedAtMs = Date.parse(statement.observedAt);
      const expiresAtMs = Date.parse(statement.expiresAt);
      if (observedAtMs > request.evaluatedAtMs + MAX_FUTURE_SKEW_MS
        || observedAtMs < request.evaluatedAtMs - MAX_AGE_MS
        || expiresAtMs <= request.evaluatedAtMs) {
        throw new Error("Recognition status attestation is not current");
      }
      let didStateVersionId: string | undefined;
      const observedResolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
        resolveResult: async (did) => {
          const result = await input.resolver.resolveResult(did);
          if (result?.didDocument?.id === statement.statusAuthorityDid) {
            const versionId = result.didDocumentMetadata.versionId;
            if (typeof versionId === "string") didStateVersionId = versionId;
          }
          return result;
        },
      };
      const method = await resolveMidnightDIDMethodBinding({
        resolver: observedResolver,
        did: parseMidnightDIDString(statement.statusAuthorityDid),
        verificationMethodId: statement.statusAuthorityMethodId,
        relationship: "assertionMethod",
      });
      if (!verifyJubjubDigest(
        method.publicKey,
        recognitionStatusAttestationDigest(statement, signed.proof.verificationMethodId),
        decodeCanonicalJubjubSignatureHex(signed.proof.signature),
      )) {
        throw new Error("Recognition status attestation signature is invalid");
      }
      if (!didStateVersionId) {
        throw new Error("Recognition status authority DID state version is unavailable");
      }
      return {
        registryId: statement.statusRegistryId,
        authorityMethodId: statement.statusAuthorityMethodId,
        statusHandleCommitment: statement.statusHandleCommitment,
        active: statement.active,
        validUntilMs: expiresAtMs,
        decisionCommitment: sha256Hex(JSON.stringify([
          "tr:recognition:verified-status-attestation:v1",
          recognitionStatusAttestationCommitment(signed),
          didStateVersionId,
        ])),
        didStateVersionId,
      };
    },
  };
}
