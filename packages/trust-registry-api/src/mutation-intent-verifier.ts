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
  try {
    const did = parseMidnightDIDString(intent.data.actorDid);
    const method = await resolveMidnightDIDMethodBinding({
      resolver,
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
