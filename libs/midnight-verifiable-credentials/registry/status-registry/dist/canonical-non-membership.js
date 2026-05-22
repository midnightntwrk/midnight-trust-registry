import { pureCircuits, } from "./managed/revocation-registry/contract/index.js";
import { buildFreshRevokedSetNonMembershipInputs, buildLiveStatusWitnessFromContractState, buildObservedRevocationRegistryState, readCurrentRevocationRegistryStateFromContractState, } from "./registry-state-observation.js";
import { StatusHelperError, statusVerificationErrorCodes, } from "./status-errors.js";
const equalBytes = (left, right) => left.length === right.length &&
    left.every((value, index) => value === right[index]);
const equalRegistryState = (left, right) => equalBytes(left.registryId, right.registryId) &&
    equalBytes(left.revokedRoot, right.revokedRoot) &&
    left.registryVersion === right.registryVersion;
const assertLiveRegistryStateMatchesBinding = ({ registryState, witness, }) => {
    if (!equalBytes(registryState.registryId, witness.statusBinding.registryRef.registryId)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Live revocation registry state does not match the status binding registry",
        });
    }
};
const assertObservedBundleConsistency = (bundle) => {
    buildObservedRevocationRegistryState(bundle.observedState);
    if (!equalRegistryState(bundle.request.registryState, bundle.protocol.request.registryState)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusRequestMismatch,
            message: "Canonical observed non-membership bundle request does not match the protocol request registry state",
        });
    }
    if (!equalBytes(bundle.request.verifierChallengeHash, bundle.protocol.request.verifierChallengeHash)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusRequestMismatch,
            message: "Canonical observed non-membership bundle request challenge does not match the protocol request challenge",
        });
    }
    if (!equalRegistryState(bundle.observedState.registryState, bundle.request.registryState)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusRequestMismatch,
            message: "Canonical observed non-membership bundle observed state does not match the request registry state",
        });
    }
    if (!equalRegistryState(bundle.witnessInput.registryState, bundle.protocol.witnessInput.registryState)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusRequestMismatch,
            message: "Canonical observed non-membership bundle witness registry state does not match the protocol witness registry state",
        });
    }
    if (!equalBytes(bundle.statusHandle, bundle.witnessInput.statusHandle)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Canonical observed non-membership bundle status handle does not match the witness input status handle",
        });
    }
    if (!equalBytes(bundle.statusHandle, bundle.protocol.witnessInput.statusHandle)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Canonical observed non-membership bundle status handle does not match the protocol witness status handle",
        });
    }
    if (!equalBytes(bundle.witnessInput.statusHandleOpening, bundle.protocol.witnessInput.statusHandleOpening)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Canonical observed non-membership bundle witness opening does not match the protocol witness opening",
        });
    }
    pureCircuits.assertValidRevokedSetNonMembershipStatusProofProtocol(bundle.protocol);
    pureCircuits.assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(bundle.statusBinding, bundle.protocol);
};
const assertLiveBundleConsistency = (bundle) => {
    pureCircuits.assertValidRevocationRegistryState(bundle.registryState);
    if (!equalBytes(bundle.witness.statusHandle, bundle.witness.witnessInput.statusHandle)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Canonical live non-membership bundle status handle does not match the witness input status handle",
        });
    }
    pureCircuits.assertLiveStatusWitnessMatchesBinding(bundle.witness.statusBinding, bundle.witness.witnessInput);
    assertLiveRegistryStateMatchesBinding({
        registryState: bundle.registryState,
        witness: bundle.witness,
    });
};
export const assertCanonicalNonMembershipBundle = (bundle) => {
    if (bundle.mode === "revokedSetObservedState") {
        assertObservedBundleConsistency(bundle);
        return;
    }
    assertLiveBundleConsistency(bundle);
};
export const buildCanonicalObservedNonMembershipBundle = (options) => {
    const bundle = {
        mode: "revokedSetObservedState",
        ...buildFreshRevokedSetNonMembershipInputs(options),
    };
    assertCanonicalNonMembershipBundle(bundle);
    return bundle;
};
export const buildCanonicalLiveNonMembershipBundleFromContractState = ({ state, ...options }) => {
    const bundle = {
        mode: "liveContractState",
        registryState: readCurrentRevocationRegistryStateFromContractState({
            state,
        }),
        witness: buildLiveStatusWitnessFromContractState({
            state,
            ...options,
        }),
    };
    assertCanonicalNonMembershipBundle(bundle);
    return bundle;
};
//# sourceMappingURL=canonical-non-membership.js.map