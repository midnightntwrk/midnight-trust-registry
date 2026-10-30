import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair } from "jose";

import { buildDecisionEvidenceClaim, type TrustedDecisionEvidenceReaders } from "@midnight-ntwrk/trust-registry-client";
import { AcceptedDecisionEpochSchema, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  buildAuthorizationSubordinateStatementPayload,
  signEntityStatement,
  verifyFederatedIssuerStatusClaim,
} from "../index.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;
const block = (label: string): string => sha256Hex(`federation-status-claim:${label}`);

const setup = async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("federation-current-issuer");
  const issuer = createIssuerScenarioFixture("federation-current-issuer");
  harness.authorizeIssuer(issuer);
  const bundle = harness.evaluateCurrentIssuerDecision(issuer);
  if (bundle.authorization?.role !== "issuer" || bundle.statusPolicyBinding === undefined) {
    throw new Error("Expected an active issuer bundle");
  }
  const epoch = harness.simulator.getEpochCommitment(bytes32Commitment(bundle.epoch.epochId));
  const witness = harness.getEpochPublicationWitness(bundle.epoch.epochId);
  const ledger = harness.simulator.getLedger();
  const networkId = issuer.subjectDid.split(":")[2]!;
  const contractAddress = `0x${harness.simulator.contractAddress}`;
  const acceptedEpoch = AcceptedDecisionEpochSchema.parse({
    registryId: harness.registryId,
    registryDid: harness.registryDid,
    networkId,
    contractAddress,
    transactionHash: block("epoch-transaction"),
    blockHash: block("epoch-block"),
    epochId: bundle.epoch.epochId,
    stateRoot: hex(epoch.stateRoot),
    eventRoot: hex(epoch.eventRoot),
    policyRoot: hex(epoch.policyRoot),
    publicationPolicyCommitment: hex(epoch.publicationPolicyCommitment),
    publicationSequence: epoch.publishedAtSequence.toString(),
    validFromSequence: epoch.validFromSequence.toString(),
    validUntilSequence: epoch.validUntilSequence.toString(),
    publicationEventHash: hex(epoch.publicationEventHash),
    validFrom: bundle.epoch.validFrom,
    validUntil: bundle.epoch.validUntil,
    requiredSignatures: Number(ledger.maintainerThreshold),
  });
  const methodId = `${issuer.subjectDid}#assertion-1`;
  const key = { kty: "EC" as const, crv: "Jubjub" as const, x: `${"A".repeat(42)}Q`, y: `${"B".repeat(42)}g` };
  const didStateBlockHash = block("did-block");
  const evidence = buildDecisionEvidenceClaim({
    bundle,
    acceptedEpoch,
    scope: issuer.authorizationScope,
    didMethod: {
      did: issuer.subjectDid,
      methodId,
      methodType: "JsonWebKey",
      controller: issuer.subjectDid,
      publicKeyJwk: key,
      relationship: "assertionMethod",
      stateVersion: "3",
      stateEvidence: { evidenceType: "ledger-observation", blockHash: didStateBlockHash, transactionHash: block("did-transaction") },
    },
    didStateBlockHash,
    publicationSignatures: witness.signatures,
    governanceEvents: {
      grantTransition: bundle.authorization.lifecycleEventRoot,
      quorumApproval: block("approval"),
      epochPublication: witness.eventHash,
      policySnapshot: bundle.epoch.policyRoot,
    },
    decisionSequence: epoch.publishedAtSequence.toString(),
  });
  const selection = {
    registryId: harness.registryId,
    networkId,
    contractAddress,
    subjectDid: issuer.subjectDid,
    role: "issuer" as const,
    resourceType: bundle.authorization.resourceType,
    resourceId: issuer.resourceId,
    scope: issuer.authorizationScope,
  };
  const currentGrant = harness.simulator.getCurrentIssuerAuthorization(
    issuer.subjectDidCommitment, issuer.resourceType, issuer.resourceIdCommitment,
  );
  const readers: TrustedDecisionEvidenceReaders = {
    readCurrentFinalizedRegistryDecision: async () => ({
      acceptedEpoch,
      publication: {
        registryIdCommitment: harness.registryIdCommitment,
        networkIdCommitment: ledger.deploymentNetworkIdCommitment,
        contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
        epochIdCommitment: bytes32Commitment(bundle.epoch.epochId),
        firstSignerKeyIdCommitment: epoch.maintainerKeyId,
        activeMaintainersAtPublication: witness.signatures.map(({ keyId }) => ({
          keyId,
          keyIdCommitment: bytes32Commitment(keyId),
          publicKey: ledger.maintainerRecords.lookup(bytes32Commitment(keyId)).publicKey,
        })),
      },
      decisionPoint: {
        sequence: epoch.publishedAtSequence.toString(),
        evaluationTime: bundle.epoch.validFrom,
        currentPolicy: { root: hex(ledger.governancePolicyCommitment), observedAtSequence: epoch.publishedAtSequence.toString() },
        currentGrant: {
          authorizationId: bundle.authorization!.authorizationId,
          lifecycleEventRoot: hex(currentGrant.lifecycleEventHash),
          status: "active",
          observedAtSequence: epoch.publishedAtSequence.toString(),
        },
      },
    }),
    readCurrentFinalizedDidState: async () => ({
      networkId,
      blockHash: didStateBlockHash,
      transactionHash: block("did-transaction"),
      stateVersion: "3",
      deactivated: false,
      didDocument: {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
        id: issuer.subjectDid,
        verificationMethod: [{ id: methodId, type: "JsonWebKey", controller: issuer.subjectDid, publicKeyJwk: key }],
        assertionMethod: [methodId],
        authentication: [methodId],
      },
    }),
  };
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "registry-federation-key";
  jwk.alg = "EdDSA";
  jwk.use = "sig";
  const jwks = { keys: [jwk] };
  const payload = buildAuthorizationSubordinateStatementPayload({
    issuerEntityId: harness.registryRecord.serviceEndpoint,
    sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
    subjectPublicJwks: jwks,
    bundle,
  });
  const jwt = await signEntityStatement({ payload, privateKey, kid: jwk.kid, alg: "EdDSA" });
  return { jwt, jwks, expectedPublisher: harness.registryRecord.serviceEndpoint, decisionEvidence: evidence, selection, readers, bundle };
};

describe("federated issuer status claim", () => {
  it("accepts a signed claim only with a current independently checked issuer grant", async () => {
    const input = await setup();
    const result = await verifyFederatedIssuerStatusClaim(input);
    expect(result.statusPolicyBinding).toEqual(input.bundle.statusPolicyBinding);
    expect(result.grantStatus).toBe("active");
  });

  it("rejects publisher substitution, unrelated evidence, and inactive current grants", async () => {
    const input = await setup();
    await expect(verifyFederatedIssuerStatusClaim({ ...input, expectedPublisher: "https://other.example" }))
      .rejects.toThrow(/publisher or subject mismatch/i);
    await expect(verifyFederatedIssuerStatusClaim({
      ...input,
      decisionEvidence: { ...input.decisionEvidence, epoch: { ...input.decisionEvidence.epoch, epochId: "epoch:other" } },
    })).rejects.toThrow(/does not match decision evidence/i);
    await expect(verifyFederatedIssuerStatusClaim({
      ...input,
      readers: {
        ...input.readers,
        readCurrentFinalizedRegistryDecision: async (...args) => {
          const snapshot = await input.readers.readCurrentFinalizedRegistryDecision(...args);
          return snapshot === null ? null : {
            ...snapshot,
            decisionPoint: {
              ...snapshot.decisionPoint,
              currentGrant: { ...snapshot.decisionPoint.currentGrant, status: "suspended" },
            },
          };
        },
      },
    })).rejects.toThrow(/current grant mismatch/i);
  });
});
