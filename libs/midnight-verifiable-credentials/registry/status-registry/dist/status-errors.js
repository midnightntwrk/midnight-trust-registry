export const statusVerificationErrorCodes = {
    revoked: "revoked",
    staleRegistryState: "staleRegistryState",
    unknownRegistry: "unknownRegistry",
    unsupportedStatusProofMode: "unsupportedStatusProofMode",
    statusBindingMismatch: "statusBindingMismatch",
    statusRequestMismatch: "statusRequestMismatch",
    authorityMismatch: "authorityMismatch",
    attestationExpired: "attestationExpired",
    attestationTooOld: "attestationTooOld",
    futureDatedAttestation: "futureDatedAttestation",
    unclassifiedFailure: "unclassifiedFailure",
};
export class StatusHelperError extends Error {
    code;
    constructor({ code, message, cause, }) {
        super(message, cause === undefined ? undefined : { cause });
        this.name = "StatusHelperError";
        this.code = code;
    }
}
//# sourceMappingURL=status-errors.js.map