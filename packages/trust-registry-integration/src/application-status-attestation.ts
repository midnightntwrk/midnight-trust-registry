import { Buffer } from "node:buffer";

import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import { verifyJubjubDigest, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex } from "@midnight-ntwrk/trust-registry-contract";
import { canonicalizeJson, sha256Hex, type IssuerStatusPolicyBinding } from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import type { ApplicationVpMaterial } from "./application-vp-verifier.js";

const Hash = z.string().regex(/^0x[0-9a-f]{64}$/u);
const Timestamp = z.string().datetime({ offset: true });
const Statement = z.strictObject({
  version: z.literal("tr-application-status-attestation-v1"),
  statusRegistryId: Hash,
  statusAuthorityMethodId: z.string().regex(/^did:midnight:[^#]+#[A-Za-z0-9:._-]+$/u),
  statusHandleCommitment: Hash,
  credentialBodyRoot: Hash,
  challengeHash: Hash,
  active: z.boolean(),
  observedAt: Timestamp,
  expiresAt: Timestamp,
});
const SignedStatement = z.strictObject({
  statement: Statement,
  proof: z.strictObject({
    verificationMethodId: Statement.shape.statusAuthorityMethodId,
    algorithm: z.literal("jubjub-schnorr"),
    signature: z.string().regex(/^0x[0-9a-f]+$/u),
  }),
});

export type ApplicationStatusStatement = z.infer<typeof Statement>;
export type SignedApplicationStatusStatement = z.infer<typeof SignedStatement>;

const field = (value: string): bigint => BigInt(`0x${sha256Hex(value).slice(2, 64)}`);
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

export function applicationStatusAttestationDigest(statement: ApplicationStatusStatement): JubjubDigest {
  const parsed = Statement.parse(statement);
  return [
    field("tr:application:status-signature:v1"),
    field(parsed.statusRegistryId),
    field(parsed.statusAuthorityMethodId),
    field(sha256Hex(canonicalizeJson(parsed))),
  ];
}

/** The caller must obtain this binding from a verified governed issuer authorization. */
export function createAttestedApplicationStatusSource(input: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  fetchAttestation: (request: {
    statusRegistryId: string;
    statusHandleCommitment: string;
    credentialBodyRoot: string;
    challengeHash: string;
  }) => Promise<unknown>;
}): (request: {
  material: ApplicationVpMaterial;
  binding: Pick<IssuerStatusPolicyBinding, "statusRegistryId" | "statusAuthorityVerificationMethod">;
  nonce: string;
  evaluatedAtMs: number;
}) => Promise<{ validUntilMs: number }> {
  return async ({ material, binding, nonce, evaluatedAtMs }) => {
    if (!/^0x[0-9a-f]{64}$/u.test(nonce) || !Number.isSafeInteger(evaluatedAtMs) || evaluatedAtMs < 0) {
      throw new Error("Application status context is invalid");
    }
    const registryId = binding.statusRegistryId;
    const methodId = binding.statusAuthorityVerificationMethod;
    if (!Hash.safeParse(registryId).success || !Statement.shape.statusAuthorityMethodId.safeParse(methodId).success) {
      throw new Error("Application status anchor is invalid");
    }
    const handle = hex(material.statusBinding.statusHandleCommitment);
    const bodyRoot = hex(material.credentialBodyRoot);
    const challengeHash = sha256Hex(Buffer.from(nonce.slice(2), "hex"));
    const signed = SignedStatement.parse(await input.fetchAttestation({
      statusRegistryId: registryId,
      statusHandleCommitment: handle,
      credentialBodyRoot: bodyRoot,
      challengeHash,
    }));
    const statement = signed.statement;
    if (hex(material.statusBinding.registryRef.registryId) !== registryId
      || statement.statusRegistryId !== registryId
      || statement.statusAuthorityMethodId !== methodId
      || statement.statusHandleCommitment !== handle
      || statement.credentialBodyRoot !== bodyRoot
      || statement.challengeHash !== challengeHash
      || signed.proof.verificationMethodId !== methodId
      || !statement.active) {
      throw new Error("Application status attestation is not active or does not match the pinned credential");
    }
    const observedAtMs = Date.parse(statement.observedAt);
    const expiresAtMs = Date.parse(statement.expiresAt);
    if (observedAtMs > evaluatedAtMs + 60_000
      || observedAtMs < evaluatedAtMs - 5 * 60_000
      || expiresAtMs <= evaluatedAtMs
      || expiresAtMs <= observedAtMs
      || expiresAtMs - observedAtMs > 5 * 60_000) {
      throw new Error("Application status attestation is not current");
    }
    const authorityDid = methodId.slice(0, methodId.indexOf("#"));
    let didStateVersionId: string | undefined;
    const method = await resolveMidnightDIDMethodBinding({
      resolver: {
        resolveResult: async (did) => {
          const result = await input.resolver.resolveResult(did);
          if (result?.didDocument?.id === authorityDid && typeof result.didDocumentMetadata.versionId === "string") {
            didStateVersionId = result.didDocumentMetadata.versionId;
          }
          return result;
        },
      },
      did: parseMidnightDIDString(authorityDid),
      verificationMethodId: methodId,
      relationship: "assertionMethod",
    });
    const pinnedRef = material.statusBinding.registryRef.authorityVerificationMethodRef;
    if (!Buffer.from(pinnedRef.controllerAddress.bytes).equals(Buffer.from(method.verificationMethodRef.controllerAddress.bytes))
      || !Buffer.from(pinnedRef.methodId).equals(Buffer.from(method.verificationMethodRef.methodId))
      || !didStateVersionId
      || !verifyJubjubDigest(
        method.publicKey,
        applicationStatusAttestationDigest(statement),
        decodeCanonicalJubjubSignatureHex(signed.proof.signature),
      )) {
      throw new Error("Application status attestation signature or DID binding is invalid");
    }
    return { validUntilMs: expiresAtMs };
  };
}
