import { type RegistryBoundStatusBinding } from "@midnight-ntwrk/midnight-did-credentials";
import { type CanonicalLiveNonMembershipBundle, type CanonicalObservedNonMembershipBundle } from "./canonical-non-membership.js";
import { type AuthorityAttestedStatusProofProtocol, type RevokedSetStatusRequest, type VerifierStatusPolicy } from "./managed/revocation-registry/contract/index.js";
import { type BuildFreshRevokedSetNonMembershipInputsOptions, type RevocationRegistryContractState } from "./registry-state-observation.js";
import { StatusHelperError, type StatusVerificationErrorCode } from "./status-errors.js";
export type StatusVerificationMode = "revokedSetObservedState" | "liveContractState" | "authorityAttested";
export declare class StatusVerificationError extends StatusHelperError {
    readonly mode: StatusVerificationMode;
    constructor({ code, mode, message, cause, }: {
        readonly code: StatusVerificationErrorCode;
        readonly mode: StatusVerificationMode;
        readonly message: string;
        readonly cause?: unknown;
    });
}
export type StatusVerificationSuccess<TDetails> = {
    readonly ok: true;
    readonly mode: StatusVerificationMode;
    readonly details: TDetails;
};
export type StatusVerificationFailure = {
    readonly ok: false;
    readonly mode: StatusVerificationMode;
    readonly error: StatusVerificationError;
};
export type StatusVerificationFailureRecord = {
    readonly mode: StatusVerificationMode;
    readonly code: StatusVerificationErrorCode;
    readonly message: string;
};
export type StatusVerificationResult<TDetails> = StatusVerificationSuccess<TDetails> | StatusVerificationFailure;
export type VerifierRegistryAcceptancePolicy = {
    readonly acceptedRegistryIds?: readonly Uint8Array[];
    readonly minimumRegistryVersion?: bigint;
};
export type AssertObservedRevokedSetStatusOptions = BuildFreshRevokedSetNonMembershipInputsOptions & {
    readonly verifierStatusPolicy: VerifierStatusPolicy;
    readonly registryAcceptancePolicy?: VerifierRegistryAcceptancePolicy;
};
export type VerifyObservedRevokedSetStatusResult = StatusVerificationResult<CanonicalObservedNonMembershipBundle>;
export type AssertLiveContractStateStatusOptions = {
    readonly credentialClaimRoot: Uint8Array;
    readonly registryRef: RegistryBoundStatusBinding["registryRef"];
    readonly issuerStatusSalt: Uint8Array;
    readonly statusHandleOpening: Uint8Array;
    readonly verifierStatusPolicy: VerifierStatusPolicy;
    readonly state: RevocationRegistryContractState;
    readonly registryAcceptancePolicy?: VerifierRegistryAcceptancePolicy;
};
export type VerifyLiveContractStateStatusResult = StatusVerificationResult<CanonicalLiveNonMembershipBundle>;
export type AssertAuthorityAttestedStatusOptions = {
    readonly statusBinding: RegistryBoundStatusBinding;
    readonly verifierStatusPolicy: VerifierStatusPolicy;
    readonly request: RevokedSetStatusRequest;
    readonly protocol: AuthorityAttestedStatusProofProtocol;
    readonly currentTime: bigint;
    readonly registryAcceptancePolicy?: VerifierRegistryAcceptancePolicy;
};
export type VerifyAuthorityAttestedStatusResult = StatusVerificationResult<AuthorityAttestedStatusProofProtocol>;
export declare const normalizeStatusVerificationFailure: ({ mode, error, }: {
    readonly mode: StatusVerificationMode;
    readonly error: unknown;
}) => StatusVerificationError;
export declare const describeStatusVerificationFailure: ({ mode, error, }: {
    readonly mode: StatusVerificationMode;
    readonly error: unknown;
}) => StatusVerificationFailureRecord;
export declare const assertObservedRevokedSetStatusVerifies: ({ registryAcceptancePolicy, verifierStatusPolicy, observedState, ...options }: AssertObservedRevokedSetStatusOptions) => CanonicalObservedNonMembershipBundle;
export declare const verifyObservedRevokedSetStatus: (options: AssertObservedRevokedSetStatusOptions) => VerifyObservedRevokedSetStatusResult;
export declare const assertLiveContractStateStatusVerifies: ({ state, registryAcceptancePolicy, verifierStatusPolicy, ...options }: AssertLiveContractStateStatusOptions) => CanonicalLiveNonMembershipBundle;
export declare const verifyLiveContractStateStatus: (options: AssertLiveContractStateStatusOptions) => VerifyLiveContractStateStatusResult;
export declare const assertAuthorityAttestedStatusVerifies: ({ statusBinding, verifierStatusPolicy, request, protocol, currentTime, registryAcceptancePolicy, }: AssertAuthorityAttestedStatusOptions) => AuthorityAttestedStatusProofProtocol;
export declare const verifyAuthorityAttestedStatus: (options: AssertAuthorityAttestedStatusOptions) => VerifyAuthorityAttestedStatusResult;
//# sourceMappingURL=status-verifier.d.ts.map