import { ledger, type RevocationRegistryState, type RevokedSetStatusRequest } from "./managed/revocation-registry/contract/index.js";
import { type BuildLiveStatusWitnessOptions, type BuildRevokedSetNonMembershipInputsOptions, type BuiltLiveStatusWitness, type BuiltRevokedSetNonMembershipInputs } from "./witness-builder.js";
export type ObservedRevocationRegistryState = {
    readonly registryState: RevocationRegistryState;
    readonly observedAt: bigint;
};
export type RevocationRegistryContractState = Parameters<typeof ledger>[0];
export type RevocationRegistrySnapshotFreshnessPolicy = {
    readonly enforceSnapshotMaxAge: boolean;
    readonly maxSnapshotAge: bigint;
};
export type BuildFreshRevokedSetNonMembershipInputsOptions = Omit<BuildRevokedSetNonMembershipInputsOptions, "registryState"> & {
    readonly observedState: ObservedRevocationRegistryState;
    readonly currentTime: bigint;
    readonly snapshotFreshnessPolicy: RevocationRegistrySnapshotFreshnessPolicy;
};
export type BuiltFreshRevokedSetNonMembershipInputs = BuiltRevokedSetNonMembershipInputs & {
    readonly observedState: ObservedRevocationRegistryState;
};
export type BuildFreshRevokedSetNonMembershipInputsFromContractStateOptions = Omit<BuildFreshRevokedSetNonMembershipInputsOptions, "observedState" | "revokedStatusHandles"> & {
    readonly state: RevocationRegistryContractState;
    readonly observedAt: bigint;
};
export type BuildLiveStatusWitnessFromContractStateOptions = Omit<BuildLiveStatusWitnessOptions, "revokedStatusHandles"> & {
    readonly state: RevocationRegistryContractState;
};
export declare const readCurrentRevocationRegistryStateFromContractState: ({ state, }: {
    readonly state: RevocationRegistryContractState;
}) => RevocationRegistryState;
export declare const buildObservedRevocationRegistryState: ({ registryState, observedAt, }: ObservedRevocationRegistryState) => ObservedRevocationRegistryState;
export declare const buildObservedRevocationRegistryStateFromContractState: ({ state, observedAt, }: {
    readonly state: RevocationRegistryContractState;
    readonly observedAt: bigint;
}) => ObservedRevocationRegistryState;
export declare const assertStatusHandleNotRevokedInContractState: ({ state, statusHandle, }: {
    readonly state: RevocationRegistryContractState;
    readonly statusHandle: Uint8Array;
}) => void;
export declare const assertObservedRevocationRegistryStateFreshEnough: ({ observedState, currentTime, policy, }: {
    readonly observedState: ObservedRevocationRegistryState;
    readonly currentTime: bigint;
    readonly policy: RevocationRegistrySnapshotFreshnessPolicy;
}) => void;
export declare const buildRevokedSetStatusRequestFromObservedState: ({ observedState, verifierChallengeHash, currentTime, snapshotFreshnessPolicy, }: {
    readonly observedState: ObservedRevocationRegistryState;
    readonly verifierChallengeHash: Uint8Array;
    readonly currentTime: bigint;
    readonly snapshotFreshnessPolicy: RevocationRegistrySnapshotFreshnessPolicy;
}) => RevokedSetStatusRequest;
export declare const assertObservedRevocationRegistryVersionAtLeast: ({ observedState, minimumRegistryVersion, }: {
    readonly observedState: ObservedRevocationRegistryState;
    readonly minimumRegistryVersion: bigint;
}) => void;
export declare const assertRevocationRegistryVersionAtLeast: ({ registryState, minimumRegistryVersion, }: {
    readonly registryState: RevocationRegistryState;
    readonly minimumRegistryVersion: bigint;
}) => void;
export declare const buildFreshRevokedSetNonMembershipInputs: ({ observedState, verifierChallengeHash, currentTime, snapshotFreshnessPolicy, ...witnessOptions }: BuildFreshRevokedSetNonMembershipInputsOptions) => BuiltFreshRevokedSetNonMembershipInputs;
export declare const buildFreshRevokedSetNonMembershipInputsFromContractState: ({ state, observedAt, ...options }: BuildFreshRevokedSetNonMembershipInputsFromContractStateOptions) => BuiltFreshRevokedSetNonMembershipInputs;
export declare const buildLiveStatusWitnessFromContractState: ({ state, ...options }: BuildLiveStatusWitnessFromContractStateOptions) => BuiltLiveStatusWitness;
//# sourceMappingURL=registry-state-observation.d.ts.map