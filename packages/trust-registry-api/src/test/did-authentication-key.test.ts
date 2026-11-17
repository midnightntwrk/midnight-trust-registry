import { describe, expect, it } from "vitest";

import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import {
  CurveType,
  encodeJubjubJwkCoordinate,
  KeyType,
  VerificationMethodType,
} from "@midnight-ntwrk/midnight-did-domain";
import { deriveJubjubPublicKeyFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import { resolvedMidnightDidSigningKey } from "../did-authentication-key.js";

const did = parseMidnightDIDString(`did:midnight:undeployed:${"a".repeat(64)}`);
const otherDid = parseMidnightDIDString(`did:midnight:undeployed:${"b".repeat(64)}`);
const keyId = `${did}#key-1`;
const key = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19));

function resolution() {
  return {
    didDocument: {
      id: did,
      verificationMethod: [{
        id: keyId,
        controller: did,
        type: VerificationMethodType.JsonWebKey,
        publicKeyJwk: {
          kty: KeyType.EC, crv: CurveType.Jubjub,
          x: encodeJubjubJwkCoordinate(key.x), y: encodeJubjubJwkCoordinate(key.y),
        },
      }],
      authentication: [keyId],
      capabilityInvocation: [keyId],
    },
    didDocumentMetadata: { deactivated: false, versionId: "1" },
  };
}

describe("DID-owned signing key resolution", () => {
  it("accepts a subject-bound, relationship-authorized native Jubjub key", () => {
    expect(resolvedMidnightDidSigningKey(resolution() as never, did, keyId, "authentication")).toEqual(key);
    expect(resolvedMidnightDidSigningKey(resolution() as never, did, keyId, "capabilityInvocation")).toEqual(key);
  });

  it("rejects a foreign subject, controller, or relationship", () => {
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocument: {
      ...resolution().didDocument, id: otherDid,
    } } as never, did, keyId, "authentication")).toThrow();
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocument: {
      ...resolution().didDocument, verificationMethod: [{ ...resolution().didDocument.verificationMethod[0]!, controller: otherDid }],
    } } as never, did, keyId, "authentication")).toThrow();
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocument: {
      ...resolution().didDocument, capabilityInvocation: [],
    } } as never, did, keyId, "capabilityInvocation")).toThrow();
  });

  it("rejects deactivation, invalid version, noncanonical method ID, and wrong key type", () => {
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocumentMetadata: {
      deactivated: true, versionId: "1",
    } } as never, did, keyId, "authentication")).toThrow();
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocumentMetadata: {
      deactivated: false, versionId: "0",
    } } as never, did, keyId, "authentication")).toThrow();
    expect(() => resolvedMidnightDidSigningKey(resolution() as never, did, "#key-1", "authentication")).toThrow();
    expect(() => resolvedMidnightDidSigningKey({ ...resolution(), didDocument: {
      ...resolution().didDocument, verificationMethod: [{ ...resolution().didDocument.verificationMethod[0]!,
        publicKeyJwk: { ...resolution().didDocument.verificationMethod[0]!.publicKeyJwk, crv: CurveType.P256 },
      }],
    } } as never, did, keyId, "authentication")).toThrow();
  });

  it("rejects a malformed same-subject method even when another method matches", () => {
    const valid = resolution();
    const malformed = { ...valid.didDocument.verificationMethod[0]!, id: `${did}/keys/key-1` };
    expect(() => resolvedMidnightDidSigningKey({ ...valid, didDocument: {
      ...valid.didDocument, verificationMethod: [malformed, ...valid.didDocument.verificationMethod],
    } } as never, did, keyId, "authentication")).toThrow(/subject fragment/u);
  });
});
