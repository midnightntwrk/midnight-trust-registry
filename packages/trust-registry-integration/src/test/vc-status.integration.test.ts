import { describe, expect, it } from "vitest";

import {
  StatusCapabilityKind,
  buildObservedRevocationRegistryState,
  deriveRevokedSetStatusHandle,
  statusVerificationErrorCodes,
  verifyObservedRevokedSetStatus,
} from "@midnight-ntwrk/midnight-did-credentials-status-registry";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client";

import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

const createAuthorityVerificationMethodRef = (label: string) => ({
  didContractAddress: {
    bytes: bytes32Commitment(`status-authority:${label}`),
  },
  methodId: bytes32Commitment(`status-authority:${label}:key-1`),
});

const createVerifierStatusPolicy = (registryId: Uint8Array) => ({
  requireStatus: true,
  acceptedStatusCapability: StatusCapabilityKind.revokedSetNonMembership,
  enforceRegistryId: true,
  acceptedRegistryId: registryId,
  enforceAttestationMaxAge: false,
  maxAttestationAge: 0n,
});

const requireReferencedStatusRegistryId = (value: string | undefined): string => {
  if (value === undefined) {
    throw new Error("expected the trust-registry bundle to reference a status registry");
  }
  return value;
};

describe("trust registry VC status integration", () => {
  it("verifies active issuer and verifier trust bundles before accepting non-revoked VC status evidence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const issuer = createIssuerScenarioFixture("degree");
    const verifier = createVerifierScenarioFixture("admissions");

    harness.authorizeIssuer(issuer);
    harness.authorizeVerifier(verifier);

    const issuerBundle = client.verifyIssuerAuthorizationBundle(
      harness.evaluateCurrentIssuerDecision(issuer),
      {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: issuer.subjectDid,
      },
    );
    const verifierBundle = client.verifyVerifierAuthorizationBundle(
      harness.evaluateCurrentVerifierDecision(verifier),
      {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: verifier.subjectDid,
      },
    );
    const referencedStatusRegistryId = requireReferencedStatusRegistryId(
      issuerBundle.referencedStatusRegistryId,
    );
    const registryId = bytes32Commitment(referencedStatusRegistryId);
    const credentialClaimRoot = bytes32Commitment("credential-root:alice:degree");
    const issuerStatusSalt = bytes32Commitment("issuer-status-salt:degree");
    const statusHandleOpening = bytes32Commitment(
      "status-handle-opening:degree",
    );

    expect(verifierBundle.authorization?.role).toBe("verifier");

    const statusResult = verifyObservedRevokedSetStatus({
      observedState: buildObservedRevocationRegistryState({
        registryState: {
          registryId,
          revokedRoot: bytes32Commitment("revoked-root:current"),
          registryVersion: 2n,
        },
        observedAt: 100n,
      }),
      verifierChallengeHash: bytes32Commitment("challenge:status"),
      currentTime: 120n,
      snapshotFreshnessPolicy: {
        enforceSnapshotMaxAge: true,
        maxSnapshotAge: 30n,
      },
      credentialClaimRoot,
      registryRef: {
        registryId,
        authorityVerificationMethodRef: createAuthorityVerificationMethodRef(
          "primary",
        ),
      },
      issuerStatusSalt,
      statusHandleOpening,
      verifierStatusPolicy: createVerifierStatusPolicy(registryId),
      revokedStatusHandles: [],
      registryAcceptancePolicy: {
        acceptedRegistryIds: [registryId],
        minimumRegistryVersion: 2n,
      },
    });

    expect(statusResult.ok).toBe(true);
    if (statusResult.ok) {
      expect(statusResult.details.statusBinding.registryRef.registryId).toEqual(
        registryId,
      );
      expect(statusResult.details.mode).toBe("revokedSetObservedState");
    }
  });

  it("rejects VC status evidence when the status registry mismatches the trusted issuer reference or the credential is revoked", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);

    const issuerBundle = client.verifyIssuerAuthorizationBundle(
      harness.evaluateCurrentIssuerDecision(issuer),
      {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: issuer.subjectDid,
      },
    );
    const acceptedRegistryId = bytes32Commitment(
      requireReferencedStatusRegistryId(issuerBundle.referencedStatusRegistryId),
    );
    const mismatchedRegistryId = bytes32Commitment("status-registry:other:v1");
    const credentialClaimRoot = bytes32Commitment(
      "credential-root:alice:passport",
    );
    const issuerStatusSalt = bytes32Commitment("issuer-status-salt:passport");
    const statusHandleOpening = bytes32Commitment(
      "status-handle-opening:passport",
    );
    const revokedHandle = deriveRevokedSetStatusHandle({
      credentialClaimRoot,
      registryId: acceptedRegistryId,
      issuerStatusSalt,
    });

    const mismatchResult = verifyObservedRevokedSetStatus({
      observedState: buildObservedRevocationRegistryState({
        registryState: {
          registryId: mismatchedRegistryId,
          revokedRoot: bytes32Commitment("revoked-root:mismatched"),
          registryVersion: 2n,
        },
        observedAt: 100n,
      }),
      verifierChallengeHash: bytes32Commitment("challenge:status"),
      currentTime: 120n,
      snapshotFreshnessPolicy: {
        enforceSnapshotMaxAge: true,
        maxSnapshotAge: 30n,
      },
      credentialClaimRoot,
      registryRef: {
        registryId: mismatchedRegistryId,
        authorityVerificationMethodRef: createAuthorityVerificationMethodRef(
          "mismatch",
        ),
      },
      issuerStatusSalt,
      statusHandleOpening,
      verifierStatusPolicy: createVerifierStatusPolicy(mismatchedRegistryId),
      revokedStatusHandles: [],
      registryAcceptancePolicy: {
        acceptedRegistryIds: [acceptedRegistryId],
        minimumRegistryVersion: 2n,
      },
    });

    expect(mismatchResult.ok).toBe(false);
    if (!mismatchResult.ok) {
      expect(mismatchResult.error.code).toBe(
        statusVerificationErrorCodes.unknownRegistry,
      );
    }

    const revokedResult = verifyObservedRevokedSetStatus({
      observedState: buildObservedRevocationRegistryState({
        registryState: {
          registryId: acceptedRegistryId,
          revokedRoot: bytes32Commitment("revoked-root:accepted"),
          registryVersion: 2n,
        },
        observedAt: 100n,
      }),
      verifierChallengeHash: bytes32Commitment("challenge:status"),
      currentTime: 120n,
      snapshotFreshnessPolicy: {
        enforceSnapshotMaxAge: true,
        maxSnapshotAge: 30n,
      },
      credentialClaimRoot,
      registryRef: {
        registryId: acceptedRegistryId,
        authorityVerificationMethodRef: createAuthorityVerificationMethodRef(
          "primary",
        ),
      },
      issuerStatusSalt,
      statusHandleOpening,
      verifierStatusPolicy: createVerifierStatusPolicy(acceptedRegistryId),
      revokedStatusHandles: [revokedHandle],
      registryAcceptancePolicy: {
        acceptedRegistryIds: [acceptedRegistryId],
        minimumRegistryVersion: 2n,
      },
    });

    expect(revokedResult.ok).toBe(false);
    if (!revokedResult.ok) {
      expect(revokedResult.error.code).toBe(
        statusVerificationErrorCodes.revoked,
      );
    }
  });
});
