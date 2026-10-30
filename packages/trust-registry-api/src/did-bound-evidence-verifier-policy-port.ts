import { Buffer } from "node:buffer";

import { MidnightNetwork } from "@midnight-ntwrk/midnight-did";
import {
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeRotateEvidenceVerifierKeyPayloadHash,
  encodeCompactActionKind,
} from "@midnight-ntwrk/trust-registry-contract";
import { EvidenceVerifierKeyStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  EvidenceVerifierDidKeyBindingError,
  verifyProposedEvidenceVerifierDidKeyBinding,
  type EvidenceVerifierDidKeyCandidate,
  type ProposedEvidenceVerifierDidKeyBindingInput,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedEvidenceVerifierRotationPrepareRequestSchema,
  GovernedPolicyActionRejectedError,
  type GovernedEvidenceVerifierTransitionInput,
  type GovernedPolicyActionContext,
  type GovernedPolicyActionPort,
} from "./governed-policy-actions.js";

const registrationKind = encodeCompactActionKind("tr:evidence-verifier:register");
const rotationKind = encodeCompactActionKind("tr:evidence-verifier:rotate");
const suite = new Uint8Array(32);
suite.set(new TextEncoder().encode("jubjub-schnorr"));
const equal = (left: Uint8Array | undefined, right: Uint8Array): boolean =>
  left !== undefined && Buffer.from(left).equals(Buffer.from(right));
const fromHex = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");
const reject = (): never => { throw new GovernedPolicyActionRejectedError(); };

export type EvidenceVerifierDidCandidate = {
  did: string;
  verificationMethodId: string;
  key: EvidenceVerifierDidKeyCandidate;
  minimumDidStateVersion?: bigint;
};

export type EvidenceVerifierRotationCandidate = EvidenceVerifierDidCandidate & {
  oldRecord: {
    authorizationId: Uint8Array;
    verifierDidCommitment: Uint8Array;
    lifecycleEventHash: Uint8Array;
    suite: Uint8Array;
    status: EvidenceVerifierKeyStatus;
  };
};

export type EvidenceVerifierDidAuthoritySource = {
  resolver: ProposedEvidenceVerifierDidKeyBindingInput["resolver"];
  expectedNetwork: MidnightNetwork;
  /** Both callbacks must read trusted current state; never derive candidates from untrusted request fields alone. */
  readRegistrationCandidate(): Promise<EvidenceVerifierDidCandidate>;
  readRotationCandidate(
    input: Extract<GovernedEvidenceVerifierTransitionInput, { action: "rotate" }>,
  ): Promise<EvidenceVerifierRotationCandidate>;
};

/** Rechecks DID authority at prepare and again immediately before Compact execution. */
export function createDidBoundEvidenceVerifierPolicyPort(
  base: GovernedPolicyActionPort,
  authority: EvidenceVerifierDidAuthoritySource,
): GovernedPolicyActionPort {
  const verifyCandidate = async (candidate: EvidenceVerifierDidCandidate): Promise<void> => {
    try {
      await verifyProposedEvidenceVerifierDidKeyBinding({
        resolver: authority.resolver,
        expectedNetwork: authority.expectedNetwork,
        did: candidate.did,
        verificationMethodId: candidate.verificationMethodId,
        candidate: candidate.key,
        ...(candidate.minimumDidStateVersion === undefined ? {} : {
          minimumDidStateVersion: candidate.minimumDidStateVersion,
        }),
      });
    } catch (error) {
      if (error instanceof EvidenceVerifierDidKeyBindingError) reject();
      throw error;
    }
  };
  const verifyRegistration = async (context: GovernedPolicyActionContext): Promise<void> => {
    const candidate = await authority.readRegistrationCandidate();
    await verifyCandidate(candidate);
    if (context.authorizationId === undefined || context.keyIdCommitment === undefined
      || context.policyVersion === undefined
      || !equal(context.actionKind, registrationKind)
      || !equal(context.keyIdCommitment, candidate.key.keyIdCommitment)
      || !equal(candidate.key.verifierDidCommitment, bytes32Commitment(candidate.did))) reject();
    const payload = computeCreateEvidenceVerifierKeyPayloadHash(
      context.authorizationId!, candidate.key.verifierDidCommitment,
      candidate.key.keyIdCommitment, candidate.key.publicKey, suite,
      context.policyCommitment, context.policyVersion!,
    );
    if (!equal(context.actionPayloadHash, payload)) reject();
  };
  const verifyRotation = async (
    input: Extract<GovernedEvidenceVerifierTransitionInput, { action: "rotate" }>,
    context: GovernedPolicyActionContext,
  ): Promise<void> => {
    const request = GovernedEvidenceVerifierRotationPrepareRequestSchema.parse({
      authorizationId: input.authorizationId,
      reasonHash: input.reasonHash,
      newAuthorizationId: input.newAuthorizationId,
      newKeyIdCommitment: input.newKeyIdCommitment,
      newPublicKey: input.newPublicKey,
    });
    const candidate = await authority.readRotationCandidate(input);
    await verifyCandidate(candidate);
    const old = candidate.oldRecord;
    if (old.status !== EvidenceVerifierKeyStatus.active
      || context.policyVersion === undefined
      || context.authorizationId === undefined || context.previousLifecycleEventHash === undefined
      || context.newAuthorizationId === undefined || context.newKeyIdCommitment === undefined
      || context.newPublicKey === undefined || context.reasonHash === undefined
      || !equal(context.actionKind, rotationKind)
      || !equal(old.authorizationId, fromHex(request.authorizationId))
      || !equal(context.authorizationId, old.authorizationId)
      || !equal(context.previousLifecycleEventHash, old.lifecycleEventHash)
      || !equal(old.verifierDidCommitment, candidate.key.verifierDidCommitment)
      || !equal(old.suite, suite)
      || !equal(context.newAuthorizationId, fromHex(request.newAuthorizationId))
      || !equal(context.newKeyIdCommitment, fromHex(request.newKeyIdCommitment))
      || !equal(context.newKeyIdCommitment, candidate.key.keyIdCommitment)
      || context.newPublicKey.x !== BigInt(request.newPublicKey.x)
      || context.newPublicKey.y !== BigInt(request.newPublicKey.y)
      || context.newPublicKey.x !== candidate.key.publicKey.x
      || context.newPublicKey.y !== candidate.key.publicKey.y
      || !equal(context.reasonHash, fromHex(request.reasonHash))) reject();
    const newPayload = computeCreateEvidenceVerifierKeyPayloadHash(
      context.newAuthorizationId!, old.verifierDidCommitment,
      candidate.key.keyIdCommitment, candidate.key.publicKey, old.suite,
      context.policyCommitment, context.policyVersion!,
    );
    const payload = computeRotateEvidenceVerifierKeyPayloadHash(
      old.authorizationId, old.lifecycleEventHash, newPayload, context.reasonHash!,
    );
    if (!equal(context.actionPayloadHash, payload)) reject();
  };

  return {
    prepareThresholds: (thresholds) => base.prepareThresholds(thresholds),
    executeThresholds: (thresholds, signers) => base.executeThresholds(thresholds, signers),
    async prepareEvidenceVerifier() {
      const context = await base.prepareEvidenceVerifier();
      await verifyRegistration(context);
      return context;
    },
    async executeEvidenceVerifier(signers) {
      await verifyRegistration(await base.prepareEvidenceVerifier());
      return base.executeEvidenceVerifier(signers);
    },
    ...(base.prepareEvidenceVerifierTransition === undefined
      || base.executeEvidenceVerifierTransition === undefined ? {} : {
      async prepareEvidenceVerifierTransition(input: GovernedEvidenceVerifierTransitionInput) {
        const context = await base.prepareEvidenceVerifierTransition!(input);
        if (input.action === "rotate") await verifyRotation(input, context);
        return context;
      },
      async executeEvidenceVerifierTransition(
        input: GovernedEvidenceVerifierTransitionInput,
        signers: Parameters<NonNullable<GovernedPolicyActionPort["executeEvidenceVerifierTransition"]>>[1],
      ) {
        if (input.action === "rotate") {
          await verifyRotation(input, await base.prepareEvidenceVerifierTransition!(input));
        }
        return base.executeEvidenceVerifierTransition!(input, signers);
      },
    }),
    ...(base.prepareMaintainerRecovery === undefined || base.executeMaintainerRecovery === undefined
      ? {} : {
        prepareMaintainerRecovery: (maintainerId: string, evidenceHash: string,
          thresholds: Parameters<NonNullable<GovernedPolicyActionPort["prepareMaintainerRecovery"]>>[2]) =>
          base.prepareMaintainerRecovery!(maintainerId, evidenceHash, thresholds),
        executeMaintainerRecovery: (maintainerId: string, evidenceHash: string,
          thresholds: Parameters<NonNullable<GovernedPolicyActionPort["executeMaintainerRecovery"]>>[2],
          signers: Parameters<NonNullable<GovernedPolicyActionPort["executeMaintainerRecovery"]>>[3]) =>
          base.executeMaintainerRecovery!(maintainerId, evidenceHash, thresholds, signers),
      }),
  };
}
