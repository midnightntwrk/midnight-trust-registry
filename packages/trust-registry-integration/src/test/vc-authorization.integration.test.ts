import { Buffer } from "node:buffer";

import {
  AuthorizationState,
  pureCircuits,
  SignerRole,
} from "@midnight-ntwrk/credential-compact";
import {
  createMidnightDIDSignerDescriptor,
  resolveMidnightDIDMethodBinding,
} from "@midnight-ntwrk/credential-did-midnight";
import {
  createMidnightDIDString,
  MidnightNetwork,
  parseContractAddress,
} from "@midnight-ntwrk/midnight-did";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client";
import { describe, expect, it } from "vitest";

import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "../did-resolution.js";
import {
  bytes32Commitment,
  createIssuerScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

const subjectDid = createMidnightDIDString(
  parseContractAddress("11".repeat(32)),
  MidnightNetwork.Testnet,
);

const requireStatusRegistryId = (value: string | undefined): string => {
  if (value === undefined) {
    throw new Error("expected the issuer bundle to reference a status registry");
  }
  return value;
};

describe("published VC and DID trust integration", () => {
  it("constructs a candidate VC signer descriptor from verified issuer and DID evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const fixture = createIssuerScenarioFixture("degree");
    const issuer = {
      ...fixture,
      subjectDid,
      subjectDidCommitment: bytes32Commitment(subjectDid),
    };
    harness.authorizeIssuer(issuer);

    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const bundle = client.verifyIssuerAuthorizationBundle(
      harness.evaluateCurrentIssuerDecision(issuer),
      {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: subjectDid,
        expectedResourceId: issuer.resourceId,
      },
    );
    expect(bundle.authorization?.authorizationId).toBe(issuer.authorizationId);

    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(subjectDid, {
        verificationMethodId: "issuer-key",
      }),
    ]);
    const method = await resolveMidnightDIDMethodBinding({
      resolver,
      did: subjectDid,
      verificationMethodId: "#issuer-key",
      relationship: "assertionMethod",
    });
    const vcScopeCommitment = pureCircuits.issuerScopeCommitment({
      packageId: bytes32Commitment("credential-package:degree"),
      schemaId: issuer.resourceIdCommitment,
      majorVersion: 1n,
      minorVersion: 0n,
    });
    const descriptor = createMidnightDIDSignerDescriptor(method, {
      authorizationId: issuer.authorizationIdCommitment,
      // The TR-to-VC sequence mapping remains a separate trust-anchor task.
      decisionSequence: 1n,
      state: AuthorizationState.active,
      role: SignerRole.issuer,
      scopeCommitment: vcScopeCommitment,
      policyCommitment: Buffer.from(bundle.epoch.policyRoot.slice(2), "hex"),
    });

    expect(pureCircuits.assertValidAuthorizedSignerDescriptor(descriptor)).toEqual([]);
    expect(descriptor.signerVerificationMethodRef).toEqual(method.verificationMethodRef);
    expect(Buffer.from(descriptor.policyCommitment).toString("hex")).toBe(bundle.epoch.policyRoot.slice(2));
    expect(pureCircuits.authorizedSignerDescriptorRoot(descriptor)).not.toEqual(
      pureCircuits.authorizedSignerDescriptorRoot({
        ...descriptor,
        scopeCommitment: bytes32Commitment("different-vc-scope"),
      }),
    );

    expect(() => createMidnightDIDSignerDescriptor(method, {
      authorizationId: issuer.authorizationIdCommitment,
      decisionSequence: 1n,
      state: AuthorizationState.active,
      role: SignerRole.verifier,
      scopeCommitment: vcScopeCommitment,
      policyCommitment: descriptor.policyCommitment,
    })).toThrow("authentication or capabilityInvocation");
    await expect(resolveMidnightDIDMethodBinding({
      resolver,
      did: subjectDid,
      verificationMethodId: "#issuer-key",
      relationship: "capabilityInvocation",
    })).rejects.toThrow("not authorized");
  });

  it("binds the VC status reference to the registry named by trusted issuer evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const fixture = createIssuerScenarioFixture("degree-status");
    const issuer = {
      ...fixture,
      subjectDid,
      subjectDidCommitment: bytes32Commitment(subjectDid),
    };
    harness.authorizeIssuer(issuer);

    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const bundle = client.verifyIssuerAuthorizationBundle(
      harness.evaluateCurrentIssuerDecision(issuer),
      {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: subjectDid,
      },
    );
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(subjectDid, {
        verificationMethodId: "status-key",
      }),
    ]);
    const method = await resolveMidnightDIDMethodBinding({
      resolver,
      did: subjectDid,
      verificationMethodId: "#status-key",
      relationship: "assertionMethod",
    });
    const acceptedRegistryId = bytes32Commitment(
      requireStatusRegistryId(bundle.referencedStatusRegistryId),
    );
    // This checks the VC commitment shape, not the status authority or revocation state.
    const binding = {
      registryRef: {
        registryId: acceptedRegistryId,
        authorityVerificationMethodRef: method.verificationMethodRef,
      },
      statusHandleCommitment: bytes32Commitment("status-handle:degree-status"),
    };

    expect(pureCircuits.assertValidRegistryBoundStatusBinding(binding)).toEqual([]);
    expect(binding.registryRef.registryId).toEqual(acceptedRegistryId);
    expect(pureCircuits.registryBoundStatusBindingRoot(binding)).not.toEqual(
      pureCircuits.registryBoundStatusBindingRoot({
        ...binding,
        registryRef: {
          ...binding.registryRef,
          registryId: bytes32Commitment("status-registry:other:v1"),
        },
      }),
    );
  });
});
