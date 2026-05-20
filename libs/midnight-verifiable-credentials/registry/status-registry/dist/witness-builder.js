import { Buffer } from "node:buffer";
import { pureCircuits, } from "./managed/revocation-registry/contract/index.js";
import { buildRegistryBoundStatusBinding } from "./status-binding.js";
import { StatusHelperError, statusVerificationErrorCodes, } from "./status-errors.js";
// Freshness of `registryState.revokedRoot` is intentionally external to this
// helper. The verifier or orchestrating application must supply an accepted
// current-enough root before calling into the proof layer.
const toHex = (value) => Buffer.from(value).toString("hex");
const equalBytes = (left, right) => left.length === right.length &&
    left.every((value, index) => value === right[index]);
export const deriveRevokedSetStatusHandle = ({ credentialClaimRoot, registryId, issuerStatusSalt, }) => pureCircuits.revokedSetStatusHandle(credentialClaimRoot, registryId, issuerStatusSalt);
export const buildRevokedSetStatusBinding = ({ registryRef, statusHandle, statusHandleOpening, }) => buildRegistryBoundStatusBinding({
    registryRef,
    statusHandleCommitment: pureCircuits.revokedSetStatusHandleCommitment(statusHandle, statusHandleOpening),
});
export const buildRevokedSetWitnessInput = ({ registryState, statusHandle, statusHandleOpening, }) => ({
    registryState,
    statusHandle,
    statusHandleOpening,
});
export const buildLiveStatusWitnessInput = ({ statusHandle, statusHandleOpening, }) => ({
    statusHandle,
    statusHandleOpening,
});
export const buildRevokedSetNonMembershipStatusProofProtocol = ({ request, witnessInput, }) => {
    const protocol = {
        request,
        witnessInput,
    };
    pureCircuits.assertValidRevokedSetNonMembershipStatusProofProtocol(protocol);
    return protocol;
};
export const buildRevokedSetStatusRequest = ({ registryState, verifierChallengeHash, }) => {
    const request = {
        registryState,
        verifierChallengeHash,
    };
    pureCircuits.assertValidRevokedSetStatusRequest(request);
    return request;
};
export const assertStatusHandleNotRevoked = (snapshot, statusHandle) => {
    const match = snapshot.revokedStatusHandles.find((candidate) => equalBytes(candidate, statusHandle));
    if (match) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.revoked,
            message: `Status handle ${toHex(statusHandle)} is already present in the revoked set snapshot`,
        });
    }
};
export const buildRevokedSetStatusWitness = ({ credentialClaimRoot, registryRef, issuerStatusSalt, statusHandleOpening, registryState, verifierStatusPolicy, revokedStatusHandles, }) => {
    const statusHandle = deriveRevokedSetStatusHandle({
        credentialClaimRoot,
        registryId: registryRef.registryId,
        issuerStatusSalt,
    });
    const statusBinding = buildRevokedSetStatusBinding({
        registryRef,
        statusHandle,
        statusHandleOpening,
    });
    const witnessInput = buildRevokedSetWitnessInput({
        registryState,
        statusHandle,
        statusHandleOpening,
    });
    pureCircuits.assertRevokedSetNonMembershipWitnessMatchesBinding(statusBinding, witnessInput);
    if (verifierStatusPolicy) {
        pureCircuits.assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding(verifierStatusPolicy, statusBinding, witnessInput);
    }
    if (revokedStatusHandles) {
        assertStatusHandleNotRevoked({
            registryState,
            revokedStatusHandles,
        }, statusHandle);
    }
    return {
        statusHandle,
        statusBinding,
        witnessInput,
    };
};
export const buildLiveStatusWitness = ({ credentialClaimRoot, registryRef, issuerStatusSalt, statusHandleOpening, verifierStatusPolicy, revokedStatusHandles, }) => {
    const statusHandle = deriveRevokedSetStatusHandle({
        credentialClaimRoot,
        registryId: registryRef.registryId,
        issuerStatusSalt,
    });
    const statusBinding = buildRevokedSetStatusBinding({
        registryRef,
        statusHandle,
        statusHandleOpening,
    });
    const witnessInput = buildLiveStatusWitnessInput({
        statusHandle,
        statusHandleOpening,
    });
    pureCircuits.assertLiveStatusWitnessMatchesBinding(statusBinding, witnessInput);
    if (verifierStatusPolicy) {
        pureCircuits.assertVerifierStatusPolicyAcceptsLiveStatusBinding(verifierStatusPolicy, statusBinding, witnessInput);
    }
    if (revokedStatusHandles) {
        assertStatusHandleNotRevoked({
            registryState: {
                registryId: registryRef.registryId,
                revokedRoot: new Uint8Array(32).fill(1),
                registryVersion: 0n,
            },
            revokedStatusHandles,
        }, statusHandle);
    }
    return {
        statusHandle,
        statusBinding,
        witnessInput,
    };
};
export const buildRevokedSetNonMembershipInputs = ({ verifierChallengeHash, ...witnessOptions }) => {
    const builtWitness = buildRevokedSetStatusWitness(witnessOptions);
    const request = buildRevokedSetStatusRequest({
        registryState: witnessOptions.registryState,
        verifierChallengeHash,
    });
    const protocol = buildRevokedSetNonMembershipStatusProofProtocol({
        request,
        witnessInput: builtWitness.witnessInput,
    });
    pureCircuits.assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(builtWitness.statusBinding, protocol);
    if (witnessOptions.verifierStatusPolicy) {
        pureCircuits.assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(witnessOptions.verifierStatusPolicy, builtWitness.statusBinding, protocol);
    }
    return {
        ...builtWitness,
        request,
        protocol,
    };
};
//# sourceMappingURL=witness-builder.js.map