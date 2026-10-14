import { Buffer } from "node:buffer";

import { createMidnightDIDHolderBinding, resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  HashHexSchema,
  RecognitionAccreditationClaimsSchema,
  RecognitionAccreditorAnchorSchema,
  assertRecognitionAccreditationClaimsMatchAnchor,
  canonicalizeJson,
  recognitionAccreditationClaimsCommitment,
  recognitionAccreditorAnchorCommitment,
  sha256Hex,
  type RecognitionAccreditorAnchor,
} from "@midnight-ntwrk/trust-registry-domain";

import { decodeApplicationVpProof } from "./application-vp-proof-json.js";
import { verifyMidnightVcVpProofs } from "./midnight-vc-vp-proof.js";

const HEX32 = /^0x[0-9a-f]{64}$/u;
const MAX_BODY_BYTES = 16_384;
const MAX_PRESENTATION_AGE_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 60_000;

export type RecognitionAccreditationSubmission = {
  rawCredentialBody: string;
  rawPresentationBody: string;
  credentialProof: unknown;
  presentationProof: unknown;
};

/** Applicant-computable commitment to the exact submitted VP, before registry evaluation. */
export function recognitionAccreditationSubmissionCommitment(input: RecognitionAccreditationSubmission): string {
  const submission = strictRecord(input, [
    "rawCredentialBody", "rawPresentationBody", "credentialProof", "presentationProof",
  ]);
  const rawCredentialBody = boundedBody(submission.rawCredentialBody);
  const rawPresentationBody = boundedBody(submission.rawPresentationBody);
  return sha256Hex(JSON.stringify([
    "tr:recognition:accreditation-submission:v1",
    rawCredentialBody,
    rawPresentationBody,
    canonicalizeJson(submission.credentialProof),
    canonicalizeJson(submission.presentationProof),
  ]));
}

export type RecognitionStatusDecision = {
  registryId: string;
  authorityMethodId: string;
  statusHandleCommitment: string;
  active: boolean;
  validUntilMs: number;
  decisionCommitment: string;
  didStateVersionId: string;
};

/** Only a trusted adapter for the anchor-pinned status source may implement this port. */
export type RecognitionAccreditationStatusSource = {
  verifyPinnedStatus(input: {
    anchor: RecognitionAccreditorAnchor;
    statusHandleCommitment: string;
    evaluatedAtMs: number;
    nonce: string;
  }): Promise<RecognitionStatusDecision>;
};

export type VerifiedRecognitionAccreditation = {
  evidenceCommitment: string;
  governedPolicyCommitment: string;
  anchorCommitment: string;
  claimsCommitment: string;
  presentationHash: string;
  accreditorDidStateVersionId: string;
  authorityDidStateVersionId: string;
  statusAuthorityDidStateVersionId: string;
  statusDecisionCommitment: string;
  evaluatedAtMs: number;
  expiresAtMs: number;
};

/** Verifies a signed accreditation VP against an independently supplied, governed anchor. */
export async function verifyRecognitionAccreditationVp(input: {
  submission: RecognitionAccreditationSubmission;
  anchor: RecognitionAccreditorAnchor;
  targetRegistryId: string;
  activePolicyCommitment: string;
  authorityDid: string;
  nonce: string;
  evaluatedAtMs: number;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  statusSource: RecognitionAccreditationStatusSource;
}): Promise<VerifiedRecognitionAccreditation> {
  const anchor = RecognitionAccreditorAnchorSchema.parse(input.anchor);
  const governedPolicyCommitment = HashHexSchema.parse(input.activePolicyCommitment).toLowerCase();
  if (anchor.targetRegistryId !== input.targetRegistryId
    || !HEX32.test(input.nonce)
    || !validTime(input.evaluatedAtMs)) {
    throw new Error("Recognition accreditation context is invalid");
  }
  const submission = strictRecord(input.submission, [
    "rawCredentialBody", "rawPresentationBody", "credentialProof", "presentationProof",
  ]);
  const rawCredentialBody = boundedBody(submission.rawCredentialBody);
  const rawPresentationBody = boundedBody(submission.rawPresentationBody);
  const credential = strictRecord(JSON.parse(rawCredentialBody) as unknown, [
    "version", "issuerMethodId", "holderMethodId", "claims",
  ]);
  const presentation = strictRecord(JSON.parse(rawPresentationBody) as unknown, [
    "version", "subjectDid", "credentialBodyRoot",
  ]);
  if (canonicalizeJson(credential) !== rawCredentialBody
    || canonicalizeJson(presentation) !== rawPresentationBody) {
    throw new Error("Recognition accreditation signed bodies must use canonical JSON");
  }
  if (credential.version !== "tr-recognition-accreditation-vp-body-v1"
    || presentation.version !== "tr-recognition-accreditation-presentation-v1") {
    throw new Error("Recognition accreditation body format is invalid");
  }
  const claims = RecognitionAccreditationClaimsSchema.parse(credential.claims);
  assertRecognitionAccreditationClaimsMatchAnchor({
    anchor, claims, authorityDid: input.authorityDid, evaluatedAtMs: input.evaluatedAtMs,
  });
  if (credential.issuerMethodId !== anchor.accreditorAssertionMethodId
    || typeof credential.holderMethodId !== "string"
    || !credential.holderMethodId.startsWith(`${claims.authorityDid}#`)
    || presentation.subjectDid !== claims.authorityDid) {
    throw new Error("Recognition accreditation DID methods or holder do not match the anchor");
  }

  const credentialBodyRoot = bytes32(rawCredentialBody);
  if (presentation.credentialBodyRoot !== hex(credentialBodyRoot)) {
    throw new Error("Recognition accreditation presentation substitutes the credential body");
  }
  const presentationBodyRoot = bytes32(rawPresentationBody);
  const credentialProof = decodeApplicationVpProof(submission.credentialProof);
  const presentationProof = decodeApplicationVpProof(submission.presentationProof);
  const challengeHash = bytes32(Buffer.from(input.nonce.slice(2), "hex"));
  if (!equalBytes(presentationProof.challengeHash, challengeHash)) {
    throw new Error("Recognition accreditation challenge does not match the VP proof");
  }
  const now = BigInt(input.evaluatedAtMs);
  if (presentationProof.createdAt > now + BigInt(MAX_FUTURE_SKEW_MS)
    || presentationProof.createdAt < now - BigInt(MAX_PRESENTATION_AGE_MS)
    || credentialProof.createdAt > now + BigInt(MAX_FUTURE_SKEW_MS)
    || credentialProof.createdAt < BigInt(Date.parse(claims.issuedAt)) - BigInt(MAX_FUTURE_SKEW_MS)) {
    throw new Error("Recognition accreditation VP proof time is invalid");
  }

  let statusAuthorityDidStateVersionId: string | null = null;
  const statusResolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
    resolveResult: async (did) => {
      const result = await input.resolver.resolveResult(did);
      const versionId = result?.didDocumentMetadata.versionId;
      if (result?.didDocument.id === anchor.statusAuthorityDid
        && typeof versionId === "string" && versionId.length > 0) {
        statusAuthorityDidStateVersionId = versionId;
      }
      return result;
    },
  };
  const [holderMethod, statusMethod] = await Promise.all([
    resolveMidnightDIDMethodBinding({
      resolver: input.resolver,
      did: parseMidnightDIDString(claims.authorityDid),
      verificationMethodId: credential.holderMethodId,
      relationship: "authentication",
    }),
    resolveMidnightDIDMethodBinding({
      resolver: statusResolver,
      did: parseMidnightDIDString(anchor.statusAuthorityDid),
      verificationMethodId: anchor.statusAuthorityMethodId,
      relationship: "assertionMethod",
    }),
  ]);
  const holderBinding = createMidnightDIDHolderBinding(holderMethod).explicitBinding;
  const verifiedProofs = await verifyMidnightVcVpProofs({
    resolver: input.resolver,
    material: {
      issuerDid: claims.accreditorDid,
      issuerMethodId: anchor.accreditorAssertionMethodId,
      subjectDid: claims.authorityDid,
      holderMethodId: credential.holderMethodId,
      credentialProof,
      presentationProof,
      credentialBodyRoot,
      presentationBodyRoot,
      credentialHolderBinding: holderBinding,
      presentationHolderBinding: holderBinding,
      statusBinding: {
        registryRef: {
          registryId: bytes32(anchor.statusRegistryId),
          authorityVerificationMethodRef: statusMethod.verificationMethodRef,
        },
        statusHandleCommitment: Buffer.from(claims.statusHandleCommitment.slice(2), "hex"),
      },
    },
  });
  if (verifiedProofs.issuerDidStateVersionId === null
    || verifiedProofs.subjectDidStateVersionId === null
    || statusAuthorityDidStateVersionId === null) {
    throw new Error("Recognition accreditation DID state version is unavailable");
  }
  const status = await input.statusSource.verifyPinnedStatus({
    anchor,
    statusHandleCommitment: claims.statusHandleCommitment,
    evaluatedAtMs: input.evaluatedAtMs,
    nonce: input.nonce,
  });
  if (!status.active || status.registryId !== anchor.statusRegistryId
    || status.authorityMethodId !== anchor.statusAuthorityMethodId
    || status.statusHandleCommitment !== claims.statusHandleCommitment
    || status.didStateVersionId !== statusAuthorityDidStateVersionId
    || !validTime(status.validUntilMs) || status.validUntilMs <= input.evaluatedAtMs) {
    throw new Error("Recognition accreditation status is not active under the anchor");
  }
  const statusDecisionCommitment = HashHexSchema.parse(status.decisionCommitment).toLowerCase();
  const anchorCommitment = recognitionAccreditorAnchorCommitment(anchor);
  const claimsCommitment = recognitionAccreditationClaimsCommitment(claims);
  const expiresAtMs = Math.min(Date.parse(claims.expiresAt), status.validUntilMs, Date.parse(anchor.effectiveUntil));
  const evidenceCommitment = sha256Hex(JSON.stringify([
    "tr:recognition:verified-accreditation-evidence:v1",
    governedPolicyCommitment,
    anchorCommitment,
    claimsCommitment,
    verifiedProofs.presentationHash,
    verifiedProofs.issuerDidStateVersionId,
    verifiedProofs.subjectDidStateVersionId,
    statusAuthorityDidStateVersionId,
    statusDecisionCommitment,
    input.evaluatedAtMs,
    expiresAtMs,
  ]));
  return {
    evidenceCommitment,
    governedPolicyCommitment,
    anchorCommitment,
    claimsCommitment,
    presentationHash: verifiedProofs.presentationHash,
    accreditorDidStateVersionId: verifiedProofs.issuerDidStateVersionId,
    authorityDidStateVersionId: verifiedProofs.subjectDidStateVersionId,
    statusAuthorityDidStateVersionId,
    statusDecisionCommitment,
    evaluatedAtMs: input.evaluatedAtMs,
    expiresAtMs,
  };
}

function strictRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Recognition accreditation body must be an object");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) {
    throw new TypeError("Recognition accreditation body has unexpected fields");
  }
  return record;
}

function boundedBody(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > MAX_BODY_BYTES) {
    throw new TypeError("Recognition accreditation body size is invalid");
  }
  return value;
}

function bytes32(value: string | Uint8Array): Uint8Array {
  return Buffer.from(sha256Hex(value).slice(2), "hex");
}

function hex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
}
