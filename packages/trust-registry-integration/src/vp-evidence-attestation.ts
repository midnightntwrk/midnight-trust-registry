import { Buffer } from "node:buffer";

import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  decodeCanonicalJubjubSignatureHex,
  encodeJubjubSignature,
  verifyApplicationEvidenceCommitmentSignature,
  type TrustRegistryJubjubSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import type {
  ApplicationEvidenceSignature,
  ApplicationEvidenceSignatureVerifier,
} from "@midnight-ntwrk/trust-registry-domain";

import { createApplicationVpIntakeVerifier, type ApplicationVpFamilyAdapter } from "./application-vp-verifier.js";

export type ApplicationVpEvidenceSigner = {
  did: string;
  keyId: string;
  publicKey: JubjubPoint;
  signCommitment: (keyIdCommitment: Uint8Array, commitment: Uint8Array) =>
    Promise<TrustRegistryJubjubSignature> | TrustRegistryJubjubSignature;
};

/** These ports plug into the API's one-use intake; they do not authorize a signer. */
export async function createApplicationVpIntakePorts<Submission>(config: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  family: ApplicationVpFamilyAdapter<Submission>;
  signer: ApplicationVpEvidenceSigner;
}) {
  const { signer } = config;
  if (!signer.keyId.startsWith(`${signer.did}#`)) {
    throw new Error("Application evidence signer key must belong to its DID");
  }
  const signerMethod = await resolveMidnightDIDMethodBinding({
    resolver: config.resolver,
    did: parseMidnightDIDString(signer.did),
    verificationMethodId: signer.keyId,
    relationship: "assertionMethod",
  });
  if (
    signerMethod.publicKey.x !== signer.publicKey.x
    || signerMethod.publicKey.y !== signer.publicKey.y
  ) {
    throw new Error("Application evidence signer key does not match its DID assertion method");
  }

  const verifyEvidenceSignature: ApplicationEvidenceSignatureVerifier = (
    commitment,
    signature,
    verifier,
  ) => {
    if (
      verifier.did !== signer.did
      || !verifier.keyIds.includes(signer.keyId)
      || signature.keyId !== signer.keyId
      || signature.algorithm !== "jubjub-schnorr"
      || !/^0x[0-9a-f]{64}$/u.test(commitment)
    ) return false;
    try {
      return verifyApplicationEvidenceCommitmentSignature(
        signer.publicKey,
        bytes32Commitment(signer.keyId),
        Buffer.from(commitment.slice(2), "hex"),
        decodeCanonicalJubjubSignatureHex(signature.value),
      );
    } catch {
      return false;
    }
  };

  return {
    verifyPresentation: createApplicationVpIntakeVerifier({
      resolver: config.resolver,
      family: config.family,
    }),
    signEvidence: async (commitment: string): Promise<ApplicationEvidenceSignature> => {
      if (!/^0x[0-9a-f]{64}$/u.test(commitment)) {
        throw new Error("Application evidence commitment must be canonical bytes32");
      }
      const keyIdCommitment = bytes32Commitment(signer.keyId);
      const commitmentBytes = Buffer.from(commitment.slice(2), "hex");
      const signed = await signer.signCommitment(keyIdCommitment, commitmentBytes);
      const signature: ApplicationEvidenceSignature = {
        keyId: signer.keyId,
        algorithm: "jubjub-schnorr",
        value: `0x${Buffer.from(encodeJubjubSignature(signed)).toString("hex")}`,
      };
      if (!verifyEvidenceSignature(commitment, signature, {
        did: signer.did, keyIds: [signer.keyId], algorithms: ["jubjub-schnorr"],
      })) {
        throw new Error("Application evidence signer produced an invalid signature");
      }
      return signature;
    },
    verifyEvidenceSignature,
  };
}
