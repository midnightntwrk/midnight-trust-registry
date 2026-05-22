import { Buffer } from "node:buffer";
import { convertFieldToBytes } from "@midnight-ntwrk/compact-runtime";
import { ledger, pureCircuits, } from "./managed/revocation-registry/contract/index.js";
import { StatusHelperError, statusVerificationErrorCodes, } from "./status-errors.js";
import { buildLiveStatusWitness, buildRevokedSetNonMembershipInputs, buildRevokedSetStatusRequest, } from "./witness-builder.js";
const assertNonNegative = (value, label) => {
    if (value < 0n) {
        throw new Error(`${label} must be >= 0`);
    }
};
const toHex = (value) => Buffer.from(value).toString("hex");
const revokedRootBytes = (currentLedger) => convertFieldToBytes(32, currentLedger.revokedStatusHandles.root().field, "revocation registry root");
export const readCurrentRevocationRegistryStateFromContractState = ({ state, }) => {
    const currentLedger = ledger(state);
    const registryState = {
        registryId: currentLedger.registryId,
        revokedRoot: revokedRootBytes(currentLedger),
        registryVersion: currentLedger.version,
    };
    pureCircuits.assertValidRevocationRegistryState(registryState);
    return registryState;
};
export const buildObservedRevocationRegistryState = ({ registryState, observedAt, }) => {
    pureCircuits.assertValidRevocationRegistryState(registryState);
    assertNonNegative(observedAt, "Observed revocation registry time");
    return {
        registryState,
        observedAt,
    };
};
export const buildObservedRevocationRegistryStateFromContractState = ({ state, observedAt, }) => buildObservedRevocationRegistryState({
    registryState: readCurrentRevocationRegistryStateFromContractState({
        state,
    }),
    observedAt,
});
export const assertStatusHandleNotRevokedInContractState = ({ state, statusHandle, }) => {
    const currentLedger = ledger(state);
    const match = currentLedger.revokedStatusHandles.findPathForLeaf(statusHandle);
    if (match) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.revoked,
            message: `Status handle ${toHex(statusHandle)} is already present in the live revocation registry state`,
        });
    }
};
export const assertObservedRevocationRegistryStateFreshEnough = ({ observedState, currentTime, policy, }) => {
    buildObservedRevocationRegistryState(observedState);
    assertNonNegative(currentTime, "Current time");
    assertNonNegative(policy.maxSnapshotAge, "Snapshot max age");
    if (currentTime < observedState.observedAt) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.staleRegistryState,
            message: "Observed revocation registry snapshot time cannot be in the future",
        });
    }
    if (policy.enforceSnapshotMaxAge) {
        const age = currentTime - observedState.observedAt;
        if (age > policy.maxSnapshotAge) {
            throw new StatusHelperError({
                code: statusVerificationErrorCodes.staleRegistryState,
                message: "Observed revocation registry snapshot exceeds the verifier max-age policy",
            });
        }
    }
};
export const buildRevokedSetStatusRequestFromObservedState = ({ observedState, verifierChallengeHash, currentTime, snapshotFreshnessPolicy, }) => {
    assertObservedRevocationRegistryStateFreshEnough({
        observedState,
        currentTime,
        policy: snapshotFreshnessPolicy,
    });
    return buildRevokedSetStatusRequest({
        registryState: observedState.registryState,
        verifierChallengeHash,
    });
};
export const assertObservedRevocationRegistryVersionAtLeast = ({ observedState, minimumRegistryVersion, }) => {
    buildObservedRevocationRegistryState(observedState);
    assertNonNegative(minimumRegistryVersion, "Minimum registry version");
    if (observedState.registryState.registryVersion < minimumRegistryVersion) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.staleRegistryState,
            message: "Observed revocation registry snapshot version is older than the required minimum",
        });
    }
};
export const assertRevocationRegistryVersionAtLeast = ({ registryState, minimumRegistryVersion, }) => {
    pureCircuits.assertValidRevocationRegistryState(registryState);
    assertNonNegative(minimumRegistryVersion, "Minimum registry version");
    if (registryState.registryVersion < minimumRegistryVersion) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.staleRegistryState,
            message: "Revocation registry state version is older than the required minimum",
        });
    }
};
export const buildFreshRevokedSetNonMembershipInputs = ({ observedState, verifierChallengeHash, currentTime, snapshotFreshnessPolicy, ...witnessOptions }) => {
    buildObservedRevocationRegistryState(observedState);
    assertObservedRevocationRegistryStateFreshEnough({
        observedState,
        currentTime,
        policy: snapshotFreshnessPolicy,
    });
    const built = buildRevokedSetNonMembershipInputs({
        ...witnessOptions,
        registryState: observedState.registryState,
        verifierChallengeHash,
    });
    return {
        ...built,
        observedState,
    };
};
export const buildFreshRevokedSetNonMembershipInputsFromContractState = ({ state, observedAt, ...options }) => {
    // Both the observed snapshot and the revoked-handle check are derived from the
    // same live contract state value passed into this helper.
    const built = buildFreshRevokedSetNonMembershipInputs({
        ...options,
        observedState: buildObservedRevocationRegistryStateFromContractState({
            state,
            observedAt,
        }),
    });
    assertStatusHandleNotRevokedInContractState({
        state,
        statusHandle: built.statusHandle,
    });
    return built;
};
export const buildLiveStatusWitnessFromContractState = ({ state, ...options }) => {
    // The live contract-state path supersedes caller-supplied revoked handle
    // snapshots and rejects directly against the current registry state.
    const built = buildLiveStatusWitness(options);
    assertStatusHandleNotRevokedInContractState({
        state,
        statusHandle: built.statusHandle,
    });
    return built;
};
//# sourceMappingURL=registry-state-observation.js.map