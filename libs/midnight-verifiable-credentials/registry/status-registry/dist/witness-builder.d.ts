import { type RegistryBoundStatusBinding, type StatusRegistryRef } from "@midnight-ntwrk/midnight-did-credentials";
import { type LiveStatusWitnessInput, type RevocationRegistryState, type RevokedSetNonMembershipStatusProofProtocol, type RevokedSetNonMembershipWitnessInput, type RevokedSetStatusRequest, type VerifierStatusPolicy } from "./managed/revocation-registry/contract/index.js";
export type RevokedSetRegistrySnapshot = {
    readonly registryState: RevocationRegistryState;
    readonly revokedStatusHandles: readonly Uint8Array[];
};
export type BuildRevokedSetStatusWitnessOptions = {
    readonly credentialClaimRoot: Uint8Array;
    readonly registryRef: StatusRegistryRef;
    readonly issuerStatusSalt: Uint8Array;
    readonly statusHandleOpening: Uint8Array;
    readonly registryState: RevocationRegistryState;
    readonly verifierStatusPolicy?: VerifierStatusPolicy;
    readonly revokedStatusHandles?: readonly Uint8Array[];
};
export type BuiltRevokedSetStatusWitness = {
    readonly statusHandle: Uint8Array;
    readonly statusBinding: RegistryBoundStatusBinding;
    readonly witnessInput: RevokedSetNonMembershipWitnessInput;
};
export type BuildLiveStatusWitnessOptions = Omit<BuildRevokedSetStatusWitnessOptions, "registryState">;
export type BuiltLiveStatusWitness = {
    readonly statusHandle: Uint8Array;
    readonly statusBinding: RegistryBoundStatusBinding;
    readonly witnessInput: LiveStatusWitnessInput;
};
export type BuildRevokedSetNonMembershipInputsOptions = BuildRevokedSetStatusWitnessOptions & {
    readonly verifierChallengeHash: Uint8Array;
};
export type BuiltRevokedSetNonMembershipInputs = BuiltRevokedSetStatusWitness & {
    readonly request: RevokedSetStatusRequest;
    readonly protocol: RevokedSetNonMembershipStatusProofProtocol;
};
export declare const deriveRevokedSetStatusHandle: ({ credentialClaimRoot, registryId, issuerStatusSalt, }: {
    readonly credentialClaimRoot: Uint8Array;
    readonly registryId: Uint8Array;
    readonly issuerStatusSalt: Uint8Array;
}) => Uint8Array;
export declare const buildRevokedSetStatusBinding: ({ registryRef, statusHandle, statusHandleOpening, }: {
    readonly registryRef: StatusRegistryRef;
    readonly statusHandle: Uint8Array;
    readonly statusHandleOpening: Uint8Array;
}) => RegistryBoundStatusBinding;
export declare const buildRevokedSetWitnessInput: ({ registryState, statusHandle, statusHandleOpening, }: {
    readonly registryState: RevocationRegistryState;
    readonly statusHandle: Uint8Array;
    readonly statusHandleOpening: Uint8Array;
}) => RevokedSetNonMembershipWitnessInput;
export declare const buildLiveStatusWitnessInput: ({ statusHandle, statusHandleOpening, }: {
    readonly statusHandle: Uint8Array;
    readonly statusHandleOpening: Uint8Array;
}) => LiveStatusWitnessInput;
export declare const buildRevokedSetNonMembershipStatusProofProtocol: ({ request, witnessInput, }: {
    readonly request: RevokedSetStatusRequest;
    readonly witnessInput: RevokedSetNonMembershipWitnessInput;
}) => RevokedSetNonMembershipStatusProofProtocol;
export declare const buildRevokedSetStatusRequest: ({ registryState, verifierChallengeHash, }: {
    readonly registryState: RevocationRegistryState;
    readonly verifierChallengeHash: Uint8Array;
}) => RevokedSetStatusRequest;
export declare const assertStatusHandleNotRevoked: (snapshot: RevokedSetRegistrySnapshot, statusHandle: Uint8Array) => void;
export declare const buildRevokedSetStatusWitness: ({ credentialClaimRoot, registryRef, issuerStatusSalt, statusHandleOpening, registryState, verifierStatusPolicy, revokedStatusHandles, }: BuildRevokedSetStatusWitnessOptions) => BuiltRevokedSetStatusWitness;
export declare const buildLiveStatusWitness: ({ credentialClaimRoot, registryRef, issuerStatusSalt, statusHandleOpening, verifierStatusPolicy, revokedStatusHandles, }: BuildLiveStatusWitnessOptions) => BuiltLiveStatusWitness;
export declare const buildRevokedSetNonMembershipInputs: ({ verifierChallengeHash, ...witnessOptions }: BuildRevokedSetNonMembershipInputsOptions) => BuiltRevokedSetNonMembershipInputs;
//# sourceMappingURL=witness-builder.d.ts.map