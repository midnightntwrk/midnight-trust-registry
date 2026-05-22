import { pureCircuits as credentialCircuits, StatusType, } from "@midnight-ntwrk/midnight-did-credentials";
import { buildCanonicalLiveNonMembershipBundleFromContractState, buildCanonicalObservedNonMembershipBundle, } from "./canonical-non-membership.js";
import { pureCircuits, } from "./managed/revocation-registry/contract/index.js";
import { assertRevocationRegistryVersionAtLeast, readCurrentRevocationRegistryStateFromContractState, } from "./registry-state-observation.js";
import { StatusHelperError, statusVerificationErrorCodes, } from "./status-errors.js";
export class StatusVerificationError extends StatusHelperError {
    mode;
    constructor({ code, mode, message, cause, }) {
        super({ code, message, cause });
        this.name = "StatusVerificationError";
        this.mode = mode;
    }
}
const equalBytes = (left, right) => left.length === right.length &&
    left.every((value, index) => value === right[index]);
const toHex = (value) => Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
const assertRegistryAccepted = ({ registryId, acceptancePolicy, }) => {
    if (acceptancePolicy?.acceptedRegistryIds === undefined) {
        return;
    }
    if (acceptancePolicy.acceptedRegistryIds.length === 0) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.unknownRegistry,
            message: "Verifier registry acceptance policy does not accept any registries",
        });
    }
    const accepted = acceptancePolicy.acceptedRegistryIds.some((candidate) => equalBytes(candidate, registryId));
    if (!accepted) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.unknownRegistry,
            message: `Registry ${toHex(registryId)} is not accepted by the verifier registry policy`,
        });
    }
};
const assertRegistryVersionAccepted = ({ registryState, acceptancePolicy, }) => {
    if (acceptancePolicy?.minimumRegistryVersion === undefined) {
        return;
    }
    assertRevocationRegistryVersionAtLeast({
        registryState,
        minimumRegistryVersion: acceptancePolicy.minimumRegistryVersion,
    });
};
const assertRegistryBoundRevocationStatusBinding = (statusBinding) => {
    credentialCircuits.assertValidRegistryBoundStatusBinding(statusBinding);
    if (statusBinding.statusType !== StatusType.revocationRegistry) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Registry-bound status binding does not use the revocation registry status type",
        });
    }
};
const assertLiveRegistryStateMatchesBinding = ({ registryState, registryRef, }) => {
    if (!equalBytes(registryState.registryId, registryRef.registryId)) {
        throw new StatusHelperError({
            code: statusVerificationErrorCodes.statusBindingMismatch,
            message: "Live revocation registry state does not match the status binding registry",
        });
    }
};
const classifyStatusVerificationError = (mode, error) => {
    if (error instanceof StatusVerificationError) {
        return error;
    }
    if (error instanceof StatusHelperError) {
        return new StatusVerificationError({
            code: error.code,
            mode,
            message: error.message,
            cause: error,
        });
    }
    const message = error instanceof Error ? error.message : String(error);
    // Keep these patterns aligned with the selected raw upstream throws pinned in
    // `src/test/status-verifier-compatibility.test.ts`. Repo-owned helper paths
    // should prefer typed `StatusHelperError`s; these regexes remain for
    // Compact/runtime surfaces that still throw plain message strings.
    const patterns = [
        [
            statusVerificationErrorCodes.unknownRegistry,
            /is not accepted by the verifier registry policy|does not accept any registries/i,
        ],
        [
            statusVerificationErrorCodes.revoked,
            /already present in the (live )?revocation registry state|already present in the revoked set snapshot|revoked in the live status registry/i,
        ],
        [
            statusVerificationErrorCodes.staleRegistryState,
            // The current taxonomy has no dedicated future-dated snapshot code yet,
            // so verifier-side snapshot-time failures stay under staleRegistryState.
            /snapshot exceeds the verifier max-age policy|snapshot version is older than the required minimum|snapshot time cannot be in the future/i,
        ],
        [
            statusVerificationErrorCodes.unsupportedStatusProofMode,
            /does not accept revoked-set non-membership|does not accept authority-attested status|does not accept live revoked-set verification|must require revoked-set status support|must require status for |request a real status capability/i,
        ],
        [
            statusVerificationErrorCodes.authorityMismatch,
            /does not match the status authority/i,
        ],
        [statusVerificationErrorCodes.attestationExpired, /has expired/i],
        [
            statusVerificationErrorCodes.attestationTooOld,
            /status proof exceeds the verifier max-age policy/i,
        ],
        [
            statusVerificationErrorCodes.futureDatedAttestation,
            /proof creation time cannot be in the future|proof timestamp cannot be in the future/i,
        ],
        [
            statusVerificationErrorCodes.statusRequestMismatch,
            /registry id does not match the verifier request|revoked root does not match the verifier request|registry version does not match the verifier request|request challenge must match the verification request challenge|does not match the request/i,
        ],
        [
            statusVerificationErrorCodes.statusBindingMismatch,
            /status handle commitment|binding handle commitment|registry-bound status binding|does not use the revocation registry status type|supplied status binding|does not match the binding|binding does not match|status binding registry/i,
        ],
    ];
    const code = patterns.find(([, pattern]) => pattern.test(message))?.[0] ??
        statusVerificationErrorCodes.unclassifiedFailure;
    return new StatusVerificationError({
        code,
        mode,
        message,
        cause: error,
    });
};
export const normalizeStatusVerificationFailure = ({ mode, error, }) => classifyStatusVerificationError(mode, error);
export const describeStatusVerificationFailure = ({ mode, error, }) => {
    const normalized = classifyStatusVerificationError(mode, error);
    return {
        mode: normalized.mode,
        code: normalized.code,
        message: normalized.message,
    };
};
export const assertObservedRevokedSetStatusVerifies = ({ registryAcceptancePolicy, verifierStatusPolicy, observedState, ...options }) => {
    assertRegistryAccepted({
        registryId: observedState.registryState.registryId,
        acceptancePolicy: registryAcceptancePolicy,
    });
    assertRegistryVersionAccepted({
        registryState: observedState.registryState,
        acceptancePolicy: registryAcceptancePolicy,
    });
    const built = buildCanonicalObservedNonMembershipBundle({
        ...options,
        observedState,
        verifierStatusPolicy,
    });
    pureCircuits.assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(verifierStatusPolicy, built.statusBinding, built.protocol);
    return built;
};
export const verifyObservedRevokedSetStatus = (options) => {
    try {
        return {
            ok: true,
            mode: "revokedSetObservedState",
            details: assertObservedRevokedSetStatusVerifies(options),
        };
    }
    catch (error) {
        return {
            ok: false,
            mode: "revokedSetObservedState",
            error: classifyStatusVerificationError("revokedSetObservedState", error),
        };
    }
};
export const assertLiveContractStateStatusVerifies = ({ state, registryAcceptancePolicy, verifierStatusPolicy, ...options }) => {
    const registryState = readCurrentRevocationRegistryStateFromContractState({
        state,
    });
    assertRegistryAccepted({
        registryId: registryState.registryId,
        acceptancePolicy: registryAcceptancePolicy,
    });
    assertRegistryVersionAccepted({
        registryState,
        acceptancePolicy: registryAcceptancePolicy,
    });
    assertLiveRegistryStateMatchesBinding({
        registryState,
        registryRef: options.registryRef,
    });
    const built = buildCanonicalLiveNonMembershipBundleFromContractState({
        state,
        ...options,
        verifierStatusPolicy,
    });
    pureCircuits.assertVerifierStatusPolicyAcceptsLiveStatusBinding(verifierStatusPolicy, built.witness.statusBinding, built.witness.witnessInput);
    return built;
};
export const verifyLiveContractStateStatus = (options) => {
    try {
        return {
            ok: true,
            mode: "liveContractState",
            details: assertLiveContractStateStatusVerifies(options),
        };
    }
    catch (error) {
        return {
            ok: false,
            mode: "liveContractState",
            error: classifyStatusVerificationError("liveContractState", error),
        };
    }
};
export const assertAuthorityAttestedStatusVerifies = ({ statusBinding, verifierStatusPolicy, request, protocol, currentTime, registryAcceptancePolicy, }) => {
    assertRegistryBoundRevocationStatusBinding(statusBinding);
    assertRegistryAccepted({
        registryId: request.registryState.registryId,
        acceptancePolicy: registryAcceptancePolicy,
    });
    assertRegistryVersionAccepted({
        registryState: request.registryState,
        acceptancePolicy: registryAcceptancePolicy,
    });
    pureCircuits.assertValidAuthorityAttestedStatusProofProtocol(protocol);
    pureCircuits.assertAuthorityAttestedStatusProofMatchesRequest(request, protocol.attestation, currentTime);
    pureCircuits.assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol(verifierStatusPolicy, statusBinding, protocol, currentTime);
    return protocol;
};
export const verifyAuthorityAttestedStatus = (options) => {
    try {
        return {
            ok: true,
            mode: "authorityAttested",
            details: assertAuthorityAttestedStatusVerifies(options),
        };
    }
    catch (error) {
        return {
            ok: false,
            mode: "authorityAttested",
            error: classifyStatusVerificationError("authorityAttested", error),
        };
    }
};
//# sourceMappingURL=status-verifier.js.map