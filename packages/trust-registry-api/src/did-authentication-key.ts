import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import {
  CurveType,
  decodeJubjubJwkCoordinate,
  KeyType,
  parseDIDURL,
  resolveDIDURLReference,
  VerificationMethodType,
  type DIDDocumentMetadata,
  type DIDKeyID,
  type VerificationMethod,
} from "@midnight-ntwrk/midnight-did-domain";

type MidnightDID = ReturnType<typeof parseMidnightDIDString>;

export interface MidnightAuthenticationResolver {
  resolveResult(did: MidnightDID): Promise<{
    didDocument: {
      id: MidnightDID;
      verificationMethod?: readonly VerificationMethod[];
      authentication?: readonly DIDKeyID[];
      capabilityInvocation?: readonly DIDKeyID[];
    };
    didDocumentMetadata: DIDDocumentMetadata;
  } | null>;
}

const UINT64_MAX = (1n << 64n) - 1n;

function subjectMethodId(reference: string, did: MidnightDID, allowExternalDID = false): string | null {
  const absolute = resolveDIDURLReference(reference, did, { allowExternalDID });
  parseDIDURL(absolute);
  if (!absolute.startsWith(`${did}#`)) {
    if (absolute === did || absolute.startsWith(`${did}/`) || absolute.startsWith(`${did}?`)) {
      throw new Error("DID key must be a subject fragment");
    }
    return null;
  }
  const fragment = absolute.slice(did.length + 1);
  if (fragment.length === 0 || fragment.includes("#")) throw new Error("Invalid DID key fragment");
  return absolute;
}

/** Resolve a DID authentication/invocation key without requiring the VC proof adapter. */
export function resolvedMidnightDidSigningKey(
  resolved: NonNullable<Awaited<ReturnType<MidnightAuthenticationResolver["resolveResult"]>>>,
  did: MidnightDID,
  actorKeyId: string,
  relationship: "authentication" | "capabilityInvocation",
): { x: bigint; y: bigint } {
  if (did.startsWith("did:midnight:offchain:") || resolved.didDocument.id !== did
    || resolved.didDocumentMetadata.deactivated === true) throw new Error("DID subject is invalid");
  const versionId = resolved.didDocumentMetadata.versionId;
  if (!/^[1-9]\d*$/u.test(versionId ?? "") || BigInt(versionId!) > UINT64_MAX) {
    throw new Error("DID version is invalid");
  }
  const methodId = subjectMethodId(actorKeyId, did);
  if (methodId === null || methodId !== actorKeyId) throw new Error("DID key is not canonical");
  const method = resolved.didDocument.verificationMethod?.find((candidate) =>
    subjectMethodId(String(candidate.id), did, true) === methodId);
  if (method === undefined || String(method.controller) !== did
    || method.type !== VerificationMethodType.JsonWebKey
    || method.publicKeyJwk.kty !== KeyType.EC
    || method.publicKeyJwk.crv !== CurveType.Jubjub
    || method.publicKeyJwk.y === undefined) throw new Error("DID signing key is invalid");
  if (!resolved.didDocument[relationship]?.some((entry) =>
    subjectMethodId(String(entry), did, true) === methodId)) {
    throw new Error("DID key is not authorized for this relationship");
  }
  return {
    x: decodeJubjubJwkCoordinate(method.publicKeyJwk.x, "Jubjub x"),
    y: decodeJubjubJwkCoordinate(method.publicKeyJwk.y, "Jubjub y"),
  };
}
