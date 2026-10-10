import {
  resolveMidnightDIDMethodBinding,
  type ResolveMidnightDIDMethodBindingOptions,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { verifyJubjubPayload } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex } from "@midnight-ntwrk/trust-registry-contract";
import {
  MutationIntentSchema,
  MutationIntentSignatureSchema,
  mutationIntentDigestBytes,
} from "@midnight-ntwrk/trust-registry-domain";

type MidnightResolver = ResolveMidnightDIDMethodBindingOptions["resolver"];

const isDeterministicDidResolutionError = (error: unknown): boolean => {
  if (!(error instanceof Error) || !(
    error.name === "ResolverRequestError" || error.name === "InvalidDIDDocumentError"
  )) return false;
  const code = (error as Error & { resolutionCode?: unknown }).resolutionCode;
  return code === "invalidDid" || code === "methodNotSupported"
    || code === "invalidPublicKey" || code === "notAllowedLocalDuplicateKey";
};

export class MutationIntentDidResolutionUnavailableError extends Error {
  constructor(cause: unknown) {
    super("Midnight DID resolver is unavailable", { cause });
    this.name = "MutationIntentDidResolutionUnavailableError";
  }
}

/** Verifies DID key control only; registry role, nonce, clock, and state checks remain separate. */
export async function verifyMutationIntentDidSignature(
  intentInput: unknown,
  signatureInput: unknown,
  resolver: MidnightResolver,
): Promise<boolean> {
  const intent = MutationIntentSchema.safeParse(intentInput);
  const signature = MutationIntentSignatureSchema.safeParse(signatureInput);
  if (!intent.success || !signature.success || signature.data.keyId !== intent.data.actorKeyId) {
    return false;
  }
  let did: ReturnType<typeof parseMidnightDIDString>;
  try {
    did = parseMidnightDIDString(intent.data.actorDid);
  } catch {
    return false;
  }

  let resolved: Awaited<ReturnType<MidnightResolver["resolveResult"]>>;
  try {
    resolved = await resolver.resolveResult(did);
  } catch (error) {
    if (isDeterministicDidResolutionError(error)) return false;
    throw new MutationIntentDidResolutionUnavailableError(error);
  }

  try {
    const method = await resolveMidnightDIDMethodBinding({
      resolver: { resolveResult: async () => resolved },
      did,
      verificationMethodId: `#${intent.data.actorKeyId.split("#")[1]}`,
      relationship: intent.data.actorRole === "applicant" ? "authentication" : "capabilityInvocation",
    });
    const digest = mutationIntentDigestBytes(intent.data);
    return verifyJubjubPayload(
      method.publicKey,
      digest,
      decodeCanonicalJubjubSignatureHex(signature.data.value),
    );
  } catch {
    return false;
  }
}
