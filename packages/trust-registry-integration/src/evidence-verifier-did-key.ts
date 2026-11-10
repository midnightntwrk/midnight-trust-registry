import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";

import {
  resolveMidnightDIDMethodBinding,
  type ResolveMidnightDIDMethodBindingOptions,
} from "@midnight-ntwrk/credential-did-midnight";
import { MidnightNetwork, parseMidnightDID, parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import { isPrimeOrderJubjubPoint } from "@midnight-ntwrk/trust-registry-contract";
import { EvidenceVerifierKeyStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

type Resolver = ResolveMidnightDIDMethodBindingOptions["resolver"];

export type EvidenceVerifierDidKeyRecord = {
  status: EvidenceVerifierKeyStatus;
  verifierDidCommitment: Uint8Array;
  keyIdCommitment: Uint8Array;
  publicKey: { x: bigint; y: bigint };
};

export type EvidenceVerifierDidKeyCandidate = Omit<EvidenceVerifierDidKeyRecord, "status">;

export type ProposedEvidenceVerifierDidKeyBindingInput = {
  resolver: Resolver;
  expectedNetwork: MidnightNetwork;
  did: string;
  verificationMethodId: string;
  candidate: EvidenceVerifierDidKeyCandidate;
  minimumDidStateVersion?: bigint;
};

export type EvidenceVerifierDidKeyBindingInput = Omit<ProposedEvidenceVerifierDidKeyBindingInput, "candidate"> & {
  registered: EvidenceVerifierDidKeyRecord;
};

export class EvidenceVerifierDidKeyBindingError extends Error {
  constructor(reason: string) {
    super(`Evidence verifier DID key binding rejected: ${reason}`);
    this.name = "EvidenceVerifierDidKeyBindingError";
  }
}

export class EvidenceVerifierDidResolutionUnavailableError extends Error {
  constructor(cause: unknown) {
    super("Evidence verifier DID resolution unavailable", { cause });
    this.name = "EvidenceVerifierDidResolutionUnavailableError";
  }
}

const matchesBytes32 = (actual: Uint8Array, expected: Uint8Array): boolean =>
  actual.length === 32 && timingSafeEqual(Buffer.from(actual), Buffer.from(expected));

/** The resolver must read an independently finalized DID state; this does not establish finality itself. */
export async function verifyProposedEvidenceVerifierDidKeyBinding(
  input: ProposedEvidenceVerifierDidKeyBindingInput,
): Promise<{ didStateVersion: bigint }> {
  let did: ReturnType<typeof parseMidnightDIDString>;
  try {
    did = parseMidnightDIDString(input.did);
    if (parseMidnightDID(did).network !== input.expectedNetwork
      || input.expectedNetwork === MidnightNetwork.Offchain) {
      throw new Error("network mismatch");
    }
  } catch {
    throw new EvidenceVerifierDidKeyBindingError("invalid or wrong-network DID");
  }
  if (!input.verificationMethodId.startsWith(`${did}#`)
    || input.verificationMethodId.slice(did.length + 1).length === 0
    || input.verificationMethodId.slice(did.length + 1).includes("#")
    || !matchesBytes32(input.candidate.verifierDidCommitment, bytes32Commitment(did))
    || !matchesBytes32(input.candidate.keyIdCommitment,
      bytes32Commitment(input.verificationMethodId))
    || !isPrimeOrderJubjubPoint(input.candidate.publicKey)) {
    throw new EvidenceVerifierDidKeyBindingError("method or registered commitment mismatch");
  }
  if (input.minimumDidStateVersion !== undefined
    && (input.minimumDidStateVersion < 1n || input.minimumDidStateVersion > (1n << 64n) - 1n)) {
    throw new EvidenceVerifierDidKeyBindingError("invalid minimum DID version");
  }

  let resolved: Awaited<ReturnType<Resolver["resolveResult"]>>;
  try {
    resolved = await input.resolver.resolveResult(did);
  } catch (error) {
    throw new EvidenceVerifierDidResolutionUnavailableError(error);
  }
  let method: Awaited<ReturnType<typeof resolveMidnightDIDMethodBinding>>;
  try {
    method = await resolveMidnightDIDMethodBinding({
      resolver: { resolveResult: async () => resolved },
      did,
      verificationMethodId: input.verificationMethodId,
      relationship: "assertionMethod",
    });
  } catch {
    throw new EvidenceVerifierDidKeyBindingError("method is not a current DID assertion key");
  }
  if (method.publicKey.x !== input.candidate.publicKey.x
    || method.publicKey.y !== input.candidate.publicKey.y
    || (input.minimumDidStateVersion !== undefined
      && method.didStateVersion < input.minimumDidStateVersion)) {
    throw new EvidenceVerifierDidKeyBindingError("resolved key or DID version mismatch");
  }
  return { didStateVersion: method.didStateVersion };
}

export async function verifyEvidenceVerifierDidKeyBinding(
  input: EvidenceVerifierDidKeyBindingInput,
): Promise<{ didStateVersion: bigint }> {
  if (input.registered.status !== EvidenceVerifierKeyStatus.active) {
    throw new EvidenceVerifierDidKeyBindingError("registered key is not active");
  }
  return verifyProposedEvidenceVerifierDidKeyBinding({
    resolver: input.resolver,
    expectedNetwork: input.expectedNetwork,
    did: input.did,
    verificationMethodId: input.verificationMethodId,
    candidate: input.registered,
    ...(input.minimumDidStateVersion === undefined ? {} : {
      minimumDidStateVersion: input.minimumDidStateVersion,
    }),
  });
}
