export declare const statusVerificationErrorCodes: {
    readonly revoked: "revoked";
    readonly staleRegistryState: "staleRegistryState";
    readonly unknownRegistry: "unknownRegistry";
    readonly unsupportedStatusProofMode: "unsupportedStatusProofMode";
    readonly statusBindingMismatch: "statusBindingMismatch";
    readonly statusRequestMismatch: "statusRequestMismatch";
    readonly authorityMismatch: "authorityMismatch";
    readonly attestationExpired: "attestationExpired";
    readonly attestationTooOld: "attestationTooOld";
    readonly futureDatedAttestation: "futureDatedAttestation";
    readonly unclassifiedFailure: "unclassifiedFailure";
};
export type StatusVerificationErrorCode = (typeof statusVerificationErrorCodes)[keyof typeof statusVerificationErrorCodes];
export declare class StatusHelperError extends Error {
    readonly code: StatusVerificationErrorCode;
    constructor({ code, message, cause, }: {
        readonly code: StatusVerificationErrorCode;
        readonly message: string;
        readonly cause?: unknown;
    });
}
//# sourceMappingURL=status-errors.d.ts.map