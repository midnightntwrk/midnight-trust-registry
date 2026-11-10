import {
  pureCircuits,
  type ExplicitHolderBinding,
  type Proof,
  type RegistryBoundStatusBinding,
} from "@midnight-ntwrk/credential-compact";
import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

export type MidnightVcVpProofMaterial = {
  issuerDid: string;
  issuerMethodId: string;
  subjectDid: string;
  holderMethodId: string;
  credentialProof: Proof;
  presentationProof: Proof;
  credentialBodyRoot: Uint8Array;
  presentationBodyRoot: Uint8Array;
  credentialHolderBinding: ExplicitHolderBinding;
  presentationHolderBinding: ExplicitHolderBinding;
  statusBinding: RegistryBoundStatusBinding;
};

/** Cryptographic proof checks only; callers must bind body claims, status, and policy. */
export async function verifyMidnightVcVpProofs(input: {
  material: MidnightVcVpProofMaterial;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
}): Promise<{
  presentationHash: string;
  issuerDidStateVersionId: string | null;
  subjectDidStateVersionId: string | null;
}> {
  const material = input.material;
  const didVersions = new Map<string, string>();
  const observedResolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
    resolveResult: async (did) => {
      const result = await input.resolver.resolveResult(did);
      const versionId = result?.didDocumentMetadata.versionId;
      if (result?.didDocument.id === did && typeof versionId === "string" && versionId.length > 0) {
        didVersions.set(did, versionId);
      }
      return result;
    },
  };
  const [issuerMethod, holderMethod] = await Promise.all([
    resolveMidnightDIDMethodBinding({
      resolver: observedResolver,
      did: parseMidnightDIDString(material.issuerDid),
      verificationMethodId: material.issuerMethodId,
      relationship: "assertionMethod",
    }),
    resolveMidnightDIDMethodBinding({
      resolver: observedResolver,
      did: parseMidnightDIDString(material.subjectDid),
      verificationMethodId: material.holderMethodId,
      relationship: "authentication",
    }),
  ]);
  assertProofMethod(material.credentialProof, issuerMethod);
  assertProofMethod(material.presentationProof, holderMethod);
  requireBytes32(material.credentialBodyRoot);
  requireBytes32(material.presentationBodyRoot);
  pureCircuits.assertValidIssuanceContextProof(material.credentialBodyRoot, material.credentialProof);
  pureCircuits.assertValidPresentationContextProof(material.presentationBodyRoot, material.presentationProof);
  pureCircuits.assertMatchingExplicitHolderBindings(
    material.credentialHolderBinding,
    material.presentationHolderBinding,
  );
  pureCircuits.assertProofMatchesExplicitHolderBinding(
    material.presentationHolderBinding,
    material.presentationProof,
  );
  pureCircuits.assertValidRegistryBoundStatusBinding(material.statusBinding);
  return {
    presentationHash: sha256Hex(pureCircuits.presentationProofPayloadRoot(
      material.presentationBodyRoot,
      material.presentationProof,
    )),
    issuerDidStateVersionId: didVersions.get(material.issuerDid) ?? null,
    subjectDidStateVersionId: didVersions.get(material.subjectDid) ?? null,
  };
}

function assertProofMethod(
  proof: Proof,
  method: Awaited<ReturnType<typeof resolveMidnightDIDMethodBinding>>,
): void {
  if (
    !equalBytes(proof.signerVerificationMethodRef.controllerAddress.bytes, method.verificationMethodRef.controllerAddress.bytes)
    || !equalBytes(proof.signerVerificationMethodRef.methodId, method.verificationMethodRef.methodId)
    || proof.publicKey.x !== method.publicKey.x
    || proof.publicKey.y !== method.publicKey.y
  ) throw new Error("Proof method does not match resolved DID method");
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function requireBytes32(value: Uint8Array): void {
  if (value.length !== 32) throw new Error("Proof body root must contain 32 bytes");
}
