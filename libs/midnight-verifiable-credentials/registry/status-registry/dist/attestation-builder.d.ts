import { type JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { type VerificationMethodRef } from "@midnight-ntwrk/midnight-did-credentials";
import { type AuthorityAttestedStatusProof, type AuthorityAttestedStatusProofProtocol, type AuthorityAttestedStatusStatement, type RevocationRegistryState, type RevokedSetStatusRequest } from "./managed/revocation-registry/contract/index.js";
export type StatusAuthoritySigner = {
    readonly secretKey: bigint;
    readonly publicKey: JubjubPoint;
    readonly verificationMethodRef: VerificationMethodRef;
};
export declare const deriveAuthorityAttestedStatusProofNonceScalar: ({ statement, signer, createdAt, }: {
    readonly statement: AuthorityAttestedStatusStatement;
    readonly signer: StatusAuthoritySigner;
    readonly createdAt: bigint;
}) => bigint;
export declare const buildAuthorityAttestedStatusRequest: ({ registryState, verifierChallengeHash, }: {
    readonly registryState: RevocationRegistryState;
    readonly verifierChallengeHash: Uint8Array;
}) => RevokedSetStatusRequest;
export declare const buildAuthorityAttestedStatusStatement: ({ request, statusHandleCommitment, expiresAt, }: {
    readonly request: RevokedSetStatusRequest;
    readonly statusHandleCommitment: Uint8Array;
    readonly expiresAt?: bigint;
}) => AuthorityAttestedStatusStatement;
/**
 * Unsafe escape hatch for tests or tightly controlled deterministic replay.
 * Production integrations should use `signAuthorityAttestedStatusProof(...)`
 * so nonce derivation stays internal to the helper.
 */
export declare const unsafeSignAuthorityAttestedStatusProofWithNonceScalar: ({ statement, signer, createdAt, nonceScalar, }: {
    readonly statement: AuthorityAttestedStatusStatement;
    readonly signer: StatusAuthoritySigner;
    readonly createdAt: bigint;
    readonly nonceScalar: bigint;
}) => AuthorityAttestedStatusProof;
export declare const signAuthorityAttestedStatusProof: ({ statement, signer, createdAt, }: {
    readonly statement: AuthorityAttestedStatusStatement;
    readonly signer: StatusAuthoritySigner;
    readonly createdAt: bigint;
}) => AuthorityAttestedStatusProof;
export declare const buildAuthorityAttestedStatusProofProtocol: ({ request, attestation, }: {
    readonly request: RevokedSetStatusRequest;
    readonly attestation: AuthorityAttestedStatusProof;
}) => AuthorityAttestedStatusProofProtocol;
//# sourceMappingURL=attestation-builder.d.ts.map