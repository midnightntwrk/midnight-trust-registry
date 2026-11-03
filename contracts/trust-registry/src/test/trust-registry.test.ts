import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { encodeContractAddress } from "@midnight-ntwrk/compact-runtime";

import {
  compareMaintainerKeyIds,
  computeCreateAuditorAuthorizationPayloadHash,
  computeAuditorEvidenceBoundProposalPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  computeCreateEpochCommitmentPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeRecognitionEvidenceBoundProposalPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeUpdateEvidenceVerifierKeyPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeVerifierEvidenceBoundProposalPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateAuditorAuthorizationPayloadHash,
  computeUpdateMaintainerMembershipPayloadHash,
  computeUpdateMaintainerThresholdPolicyPayloadHash,
  computeRecoverMaintainerMembershipPayloadHash,
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  computeDeploymentBoundMaintainerActionDigest,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  signRecognitionProposalEvidenceFromSeed,
  signAuditorProposalEvidenceFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  signVerifierProposalEvidenceFromSeed,
  verifyDeploymentBoundMaintainerAction,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  type MaintainerCoAuthorizer,
  TrustRegistrySimulator,
} from "../testing.js";
import {
  AuthorizationStatus,
  IssuerResourceType,
  MaintainerStatus,
  pureCircuits,
} from "../managed/trust-registry/contract/index.js";

import { describe, expect, it } from "vitest";

const FIXTURE_NETWORK_ID_COMMITMENT = labelToBytes32("network:undeployed");
const signFixtureDeploymentBoundActionFromSeed = (
  simulator: TrustRegistrySimulator,
  seed: Uint8Array, registryId: Uint8Array, policyCommitment: Uint8Array,
  actionKind: Uint8Array, payloadHash: Uint8Array, sequence: bigint,
) => signDeploymentBoundMaintainerActionFromSeed(
  seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
  policyCommitment, actionKind, payloadHash, sequence,
);
const verifyFixtureDeploymentBoundAction = (
  simulator: TrustRegistrySimulator,
  publicKey: ReturnType<typeof deriveJubjubPublicKeyFromSeed>, registryId: Uint8Array,
  policyCommitment: Uint8Array, actionKind: Uint8Array, payloadHash: Uint8Array,
  sequence: bigint, signature: ReturnType<typeof signDeploymentBoundMaintainerActionFromSeed>,
) => verifyDeploymentBoundMaintainerAction(
  publicKey, registryId, FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
  policyCommitment, actionKind, payloadHash, sequence, signature,
);

it("encodes Compact action kinds exactly and rejects overlong values", () => {
  expect(encodeCompactActionKind("tr:epoch:publish")).toEqual(labelToBytes32("tr:epoch:publish"));
  expect(() => encodeCompactActionKind(`tr:${"x".repeat(30)}`)).toThrow(/exceeds Compact Bytes<32>/);
});

it("uses the default meta-governance quorum for threshold policy revisions", () => {
  const updateKind = encodeCompactActionKind("tr:policy:thresholds:update");
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 1n, 2n, 3n)).toBe(1n);
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 3n, 2n, 1n)).toBe(3n);
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 1n, 3n, 2n)).toBe(1n);
  expect(pureCircuits.actionScopedMaintainerThreshold(
    encodeCompactActionKind("tr:issuer:authorize"), 1n, 2n, 3n,
  )).toBe(1n);
});

it("requires both current policy and emergency quorums for atomic recovery", () => {
  expect(pureCircuits.actionScopedMaintainerThreshold(
    RECOVER_MAINTAINER_ACTION_KIND, 2n, 3n, 2n,
  )).toBe(3n);
  expect(pureCircuits.actionScopedMaintainerThreshold(
    RECOVER_MAINTAINER_ACTION_KIND, 3n, 2n, 2n,
  )).toBe(3n);
});

it("rejects malformed fixture labels before UTF-8 replacement can alias them", () => {
  expect(() => labelToBytes32(`${"x".repeat(31)}\ud800`)).toThrow(/valid UTF-16/);
  expect(() => labelToBytes32(`${"x".repeat(31)}\udc00`)).toThrow(/valid UTF-16/);
  expect(labelToBytes32("valid-\ud83d\ude00")).toHaveLength(32);
});

it("hashes only strictly sorted, distinct maintainer key ids with zero padding", () => {
  const zero = new Uint8Array(32);
  const first = new Uint8Array(32);
  first[31] = 1;
  const second = new Uint8Array(32);
  second[0] = 0x80;
  const third = new Uint8Array(32);
  third[0] = 0xff;
  const hash = pureCircuits.maintainerSignerSetHash(3n, second, third, first, zero, zero);
  expect(hash).toHaveLength(32);
  expect(Buffer.from(pureCircuits.maintainerSignerSetHash(2n, second, first, zero, zero, zero))
    .toString("hex")).toBe("a2a083e62cd7a8c2e3dcca00448fc2b20c4e59e295cdbbedbdd3f34f74430d80");
  expect(() => pureCircuits.maintainerSignerSetHash(3n, third, second, first, zero, zero))
    .toThrow(/must be sorted/);
  expect(() => pureCircuits.maintainerSignerSetHash(3n, second, third, third, zero, zero))
    .toThrow(/must be sorted/);
  expect(() => pureCircuits.maintainerSignerSetHash(2n, second, third, first, zero, zero))
    .toThrow(/must be zero/);
  expect(() => pureCircuits.maintainerSignerSetHash(1n, zero, zero, zero, zero, zero))
    .toThrow(/nonzero/);
});

const PROPOSE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:propose");
const AUTHORIZE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:authorize");
const ACTIVATE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:activate");
const SUSPEND_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:archive");
const PROPOSE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:propose");
const AUTHORIZE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:authorize");
const ACTIVATE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:activate");
const SUSPEND_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:suspend");
const REVOKE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:revoke");
const ARCHIVE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:archive");
const PROPOSE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:propose");
const AUTHORIZE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:authorize");
const ACTIVATE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:activate");
const SUSPEND_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:suspend");
const REVOKE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:revoke");
const ARCHIVE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:archive");
const PROPOSE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:propose");
const AUTHORIZE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:authorize");
const ACTIVATE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:activate");
const SUSPEND_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:suspend");
const REVOKE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:revoke");
const ARCHIVE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:archive");
const PROPOSE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:propose");
const AUTHORIZE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:authorize");
const ACTIVATE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:activate");
const SUSPEND_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:suspend");
const REVOKE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:revoke");
const ARCHIVE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:archive");
const REGISTER_EVIDENCE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:evidence-verifier:register");
const SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:evidence-verifier:suspend");
const REVOKE_EVIDENCE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:evidence-verifier:revoke");
const ROTATE_EVIDENCE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:evidence-verifier:rotate");
const REGISTER_VC_AUTHORITY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:register");
const SUSPEND_VC_AUTHORITY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:suspend");
const REVOKE_VC_AUTHORITY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:revoke");
const ROTATE_VC_AUTHORITY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:rotate");
const UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND = encodeCompactActionKind(
  "tr:policy:thresholds:update",
);
const RECOVER_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:recover");
const CREATE_EPOCH_ACTION_KIND = encodeCompactActionKind("tr:epoch:publish");
const GENERIC_AUDIT_ACTION_KIND = encodeCompactActionKind("tr:audit:generic");

it("pins every governed action kind to a Compact literal", () => {
  const compactSource = readFileSync(new URL("../trust-registry.compact", import.meta.url), "utf8");
  const compactKinds = [...compactSource.matchAll(
    /performAuthorizedMaintainerAction\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*pad\(\s*32\s*,\s*"(tr:[^"]+)"\s*\)/g,
  )].map((match) => match[1]!);
  expect(compactKinds).toHaveLength(
    [...compactSource.matchAll(/performAuthorizedMaintainerAction\(/g)].length - 1,
  );
  const expected = [
    PROPOSE_ISSUER_ACTION_KIND, AUTHORIZE_ISSUER_ACTION_KIND, ACTIVATE_ISSUER_ACTION_KIND,
    SUSPEND_ISSUER_ACTION_KIND, REVOKE_ISSUER_ACTION_KIND, ARCHIVE_ISSUER_ACTION_KIND,
    PROPOSE_VERIFIER_ACTION_KIND, AUTHORIZE_VERIFIER_ACTION_KIND, ACTIVATE_VERIFIER_ACTION_KIND,
    SUSPEND_VERIFIER_ACTION_KIND, REVOKE_VERIFIER_ACTION_KIND, ARCHIVE_VERIFIER_ACTION_KIND,
    PROPOSE_RECOGNITION_ACTION_KIND, AUTHORIZE_RECOGNITION_ACTION_KIND, ACTIVATE_RECOGNITION_ACTION_KIND,
    SUSPEND_RECOGNITION_ACTION_KIND, REVOKE_RECOGNITION_ACTION_KIND, ARCHIVE_RECOGNITION_ACTION_KIND,
    PROPOSE_AUDITOR_ACTION_KIND, AUTHORIZE_AUDITOR_ACTION_KIND, ACTIVATE_AUDITOR_ACTION_KIND,
    SUSPEND_AUDITOR_ACTION_KIND, REVOKE_AUDITOR_ACTION_KIND, ARCHIVE_AUDITOR_ACTION_KIND,
    PROPOSE_MAINTAINER_ACTION_KIND, AUTHORIZE_MAINTAINER_ACTION_KIND, ACTIVATE_MAINTAINER_ACTION_KIND,
    SUSPEND_MAINTAINER_ACTION_KIND, REVOKE_MAINTAINER_ACTION_KIND, ARCHIVE_MAINTAINER_ACTION_KIND,
    RECOVER_MAINTAINER_ACTION_KIND,
    REGISTER_EVIDENCE_VERIFIER_ACTION_KIND, SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
    REVOKE_EVIDENCE_VERIFIER_ACTION_KIND, ROTATE_EVIDENCE_VERIFIER_ACTION_KIND,
    REGISTER_VC_AUTHORITY_ACTION_KIND, SUSPEND_VC_AUTHORITY_ACTION_KIND,
    REVOKE_VC_AUTHORITY_ACTION_KIND, ROTATE_VC_AUTHORITY_ACTION_KIND,
    UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, CREATE_EPOCH_ACTION_KIND, GENERIC_AUDIT_ACTION_KIND,
  ];
  expect(new Set(compactKinds.map((kind) => Buffer.from(encodeCompactActionKind(kind)).toString("hex"))))
    .toEqual(new Set(expected.map((kind) => Buffer.from(kind).toString("hex"))));
});

const createInitializedRegistryFixture = (seedByte: number) => {
  const registryId = labelToBytes32("registry:kanon");
  const registryDidCommitment = labelToBytes32("did:midnight:registry");
  const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
  const bootstrapMaintainer = createMaintainerFixture("bootstrap", seedByte);
  const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
    bootstrapMaintainer.seed,
  );

  const simulator = new TrustRegistrySimulator({
    registryId,
    networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
    registryDidCommitment,
    governancePolicyCommitment,
    maintainerId: bootstrapMaintainer.maintainerId,
    maintainerDidCommitment: bootstrapMaintainer.didCommitment,
    maintainerKeyId: bootstrapMaintainer.keyId,
    maintainerPublicKey: bootstrapPublicKey,
    maintainerThreshold: 1n,
  });

  return {
    simulator,
    registryId,
    registryDidCommitment,
    governancePolicyCommitment,
    bootstrapMaintainer,
    bootstrapPublicKey,
  };
};

const createIssuerAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`issuer-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:issuer:${label}`),
  resourceType: IssuerResourceType.credentialFamily,
  resourceId: labelToBytes32(`vc-type:${label}:v1`),
  policyId: labelToBytes32("policy:kanon:v1"),
  statusPolicyBindingCommitment: labelToBytes32(`issuer-status-policy:${label}`),
  trustLevel: labelToBytes32("approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

type RegistryFixture = ReturnType<typeof createInitializedRegistryFixture>;
type IssuerFixture = ReturnType<typeof createIssuerAuthorizationFixture>;
const evidenceVerifiers = new WeakMap<TrustRegistrySimulator, ReturnType<typeof createMaintainerFixture> & {
  authorizationId: Uint8Array;
  publicKey: ReturnType<typeof deriveJubjubPublicKeyFromSeed>;
}>();

const registerIssuerEvidenceVerifier = (
  registry: RegistryFixture,
  coMaintainer?: ReturnType<typeof createMaintainerMembershipFixture>,
) => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const existing = evidenceVerifiers.get(simulator);
  const policyCommitment = simulator.getLedger().governancePolicyCommitment;
  const policyVersion = simulator.getLedger().governancePolicyVersion;
  if (existing && simulator.getEvidenceVerifierKey(existing.authorizationId).policyVersion === policyVersion) {
    return existing;
  }
  const verifier = {
    ...createMaintainerFixture("issuer-evidence-verifier", 97),
    authorizationId: labelToBytes32(`evidence-verifier:issuer:v${policyVersion}`),
    keyId: labelToBytes32(`evidence-verifier:key:v${policyVersion}`),
    publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(97)),
  };
  const payloadHash = computeCreateEvidenceVerifierKeyPayloadHash(
    verifier.authorizationId, verifier.didCommitment, verifier.keyId, verifier.publicKey,
    labelToBytes32("jubjub-schnorr"), policyCommitment, policyVersion,
  );
  const sequence = simulator.getLedger().governanceActionCount;
  simulator.registerEvidenceVerifierKey(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, policyCommitment,
      REGISTER_EVIDENCE_VERIFIER_ACTION_KIND, payloadHash, sequence,
    ),
    verifier.authorizationId, verifier.didCommitment, verifier.keyId, verifier.publicKey,
    labelToBytes32("jubjub-schnorr"), policyCommitment, policyVersion,
    coMaintainer ? [createMaintainerCoAuthorizer(
      coMaintainer, simulator, registryId, REGISTER_EVIDENCE_VERIFIER_ACTION_KIND,
      payloadHash, sequence,
    )] : [],
  );
  evidenceVerifiers.set(simulator, verifier);
  return verifier;
};

const issuerProposalProof = (
  registry: RegistryFixture,
  issuer: IssuerFixture,
  verifier: ReturnType<typeof registerIssuerEvidenceVerifier>,
) => {
  const { simulator, registryId } = registry;
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
    issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
    issuer.trustLevel, issuer.evidenceHash,
  );
  const payloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return {
    payloadHash,
    verifierAuthorizationId: verifier.authorizationId,
    verifierKeyIdCommitment: verifier.keyId,
    evidenceSignature: signIssuerProposalEvidenceFromSeed(
      verifier.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress), verifier.keyId, payloadHash,
    ),
  };
};

const recognitionProposalProof = (
  registry: RegistryFixture,
  recognition: ReturnType<typeof createRecognitionFixture>,
  evidenceHash: Uint8Array,
) => {
  const verifier = registerIssuerEvidenceVerifier(registry);
  const { simulator, registryId } = registry;
  const baseHash = computeCreateRecognitionPayloadHash(
    recognition.recognitionId,
    recognition.recognizedAuthorityDidCommitment,
    recognition.recognizedRegistryId,
    recognition.scopeResourceType,
    recognition.scopeResourceId,
    recognition.policyId,
    recognition.trustLevel,
    evidenceHash,
  );
  const payloadHash = computeRecognitionEvidenceBoundProposalPayloadHash(
    baseHash,
    verifier.authorizationId,
    verifier.keyId,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return {
    payloadHash,
    verifierAuthorizationId: verifier.authorizationId,
    verifierKeyIdCommitment: verifier.keyId,
    evidenceSignature: signRecognitionProposalEvidenceFromSeed(
      verifier.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress), verifier.keyId, payloadHash,
    ),
  };
};

const verifierProposalProof = (
  registry: RegistryFixture,
  verifierAuthorization: ReturnType<typeof createVerifierAuthorizationFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = registerIssuerEvidenceVerifier(registry);
  const baseHash = computeCreateVerifierAuthorizationPayloadHash(
    verifierAuthorization.authorizationId,
    verifierAuthorization.subjectDidCommitment,
    verifierAuthorization.requestResourceId,
    verifierAuthorization.allowedAttributeSetCommitment,
    verifierAuthorization.allowedPredicateSetCommitment,
    verifierAuthorization.disclosureLevelCommitment,
    verifierAuthorization.policyId,
    verifierAuthorization.trustLevel,
    verifierAuthorization.evidenceHash,
  );
  const payloadHash = computeVerifierEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return {
    payloadHash,
    verifierAuthorizationId: verifier.authorizationId,
    verifierKeyIdCommitment: verifier.keyId,
    evidenceSignature: signVerifierProposalEvidenceFromSeed(
      verifier.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress), verifier.keyId, payloadHash,
    ),
  };
};

const activateIssuerAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createIssuerAuthorizationFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = issuerProposalProof(
    registry, authorization, registerIssuerEvidenceVerifier(registry),
  );
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );

  simulator.proposeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.resourceType,
    authorization.resourceId,
    authorization.policyId,
    authorization.statusPolicyBindingCommitment,
    authorization.trustLevel,
    authorization.evidenceHash,
    proof.verifierAuthorizationId,
    proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  simulator.authorizeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getIssuerAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return simulator.activateIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getIssuerAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
};

const createVerifierAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`verifier-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:verifier:${label}`),
  requestResourceId: labelToBytes32(`request-resource:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`pred-set:${label}:adult`),
  disclosureLevelCommitment: labelToBytes32(`disclosure:${label}:selective`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const createRecognitionFixture = (label: string) => ({
  recognitionId: labelToBytes32(`recognition:${label}`),
  recognizedAuthorityDidCommitment: labelToBytes32(
    `did:web:${label}.authority.example`,
  ),
  recognizedRegistryId: labelToBytes32(`registry:external:${label}:v1`),
  scopeResourceType: labelToBytes32("recognized-scope"),
  scopeResourceId: labelToBytes32(`credential-family:${label}:v1`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("peer-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const activateVerifierAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createVerifierAuthorizationFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = verifierProposalProof(registry, authorization);
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  simulator.proposeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_VERIFIER_ACTION_KIND, proof.payloadHash),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.requestResourceId,
    authorization.allowedAttributeSetCommitment,
    authorization.allowedPredicateSetCommitment,
    authorization.disclosureLevelCommitment,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
    proof.verifierAuthorizationId,
    proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  simulator.authorizeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getVerifierAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return simulator.activateVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getVerifierAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
};

const activateRecognitionFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  recognition: ReturnType<typeof createRecognitionFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = recognitionProposalProof(registry, recognition, recognition.evidenceHash);
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  simulator.proposeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_RECOGNITION_ACTION_KIND, proof.payloadHash),
    recognition.recognitionId,
    recognition.recognizedAuthorityDidCommitment,
    recognition.recognizedRegistryId,
    recognition.scopeResourceType,
    recognition.scopeResourceId,
    recognition.policyId,
    recognition.trustLevel,
    recognition.evidenceHash,
    proof.verifierAuthorizationId,
    proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  simulator.authorizeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      simulator.getRecognition(recognition.recognitionId).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  );
  return simulator.activateRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      simulator.getRecognition(recognition.recognitionId).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  );
};

const createAuditorAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`auditor-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:auditor:${label}`),
  requestResourceId: labelToBytes32(`audit-request-resource:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`audit-attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`audit-pred-set:${label}:compliance`),
  disclosureLevelCommitment: labelToBytes32(`audit-disclosure:${label}:restricted`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("audit-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const auditorProposalProof = (
  registry: RegistryFixture,
  auditor: ReturnType<typeof createAuditorAuthorizationFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = registerIssuerEvidenceVerifier(registry);
  const baseHash = computeCreateAuditorAuthorizationPayloadHash(
    auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
    auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
    auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel, auditor.evidenceHash,
  );
  const payloadHash = computeAuditorEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return {
    payloadHash,
    verifierAuthorizationId: verifier.authorizationId,
    verifierKeyIdCommitment: verifier.keyId,
    evidenceSignature: signAuditorProposalEvidenceFromSeed(
      verifier.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress), verifier.keyId, payloadHash,
    ),
  };
};

const activateAuditorAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createAuditorAuthorizationFixture>,
): void => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = auditorProposalProof(registry, authorization);
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  simulator.proposeAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.requestResourceId,
    authorization.allowedAttributeSetCommitment,
    authorization.allowedPredicateSetCommitment,
    authorization.disclosureLevelCommitment,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
    proof.verifierAuthorizationId,
    proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  simulator.authorizeAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_AUDITOR_ACTION_KIND, computeUpdateAuditorAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getAuditorAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  simulator.activateAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_AUDITOR_ACTION_KIND, computeUpdateAuditorAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getAuditorAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
};

const createMaintainerMembershipFixture = (label: string, seedByte: number) => {
  const candidate = createMaintainerFixture(label, seedByte);
  return {
    maintainerId: candidate.maintainerId,
    maintainerDidCommitment: candidate.didCommitment,
    keyId: candidate.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(candidate.seed),
    policyId: labelToBytes32("policy:kanon:v1"),
    trustLevel: labelToBytes32("governance-approved"),
    evidenceHash: labelToBytes32(`evidence:${label}:propose`),
    seed: candidate.seed,
  };
};

const maintainerProposalProof = (
  registry: RegistryFixture,
  candidate: ReturnType<typeof createMaintainerMembershipFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = registerIssuerEvidenceVerifier(registry);
  const baseHash = computeCreateMaintainerMembershipPayloadHash(
    candidate.maintainerId, candidate.maintainerDidCommitment, candidate.keyId,
    candidate.publicKey, candidate.policyId, candidate.trustLevel, candidate.evidenceHash,
  );
  const payloadHash = computeMaintainerEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return {
    payloadHash,
    verifierAuthorizationId: verifier.authorizationId,
    verifierKeyIdCommitment: verifier.keyId,
    evidenceSignature: signMaintainerProposalEvidenceFromSeed(
      verifier.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress), verifier.keyId, payloadHash,
    ),
  };
};

const createMaintainerCoAuthorizer = (
  maintainer: ReturnType<typeof createMaintainerMembershipFixture>,
  simulator: TrustRegistrySimulator,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: maintainer.publicKey,
  signature: signFixtureDeploymentBoundActionFromSeed(simulator,
    maintainer.seed,
    registryId,
    simulator.getLedger().governancePolicyCommitment,
    actionKind,
    actionPayloadHash,
    actionSequence,
  ),
});

const activateAdditionalMaintainer = (
  registry: RegistryFixture,
  candidate: ReturnType<typeof createMaintainerMembershipFixture>,
): void => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = (kind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId,
      simulator.getLedger().governancePolicyCommitment,
      kind, payloadHash, simulator.getLedger().governanceActionCount,
    );
  const proof = maintainerProposalProof(registry, candidate);
  simulator.proposeMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey, sign(PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash),
    candidate.maintainerId, candidate.maintainerDidCommitment,
    candidate.keyId, candidate.publicKey, candidate.policyId, candidate.trustLevel,
    candidate.evidenceHash, proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  const authorizeRecord = simulator.getMaintainerMembership(candidate.maintainerId);
  simulator.authorizeMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    sign(AUTHORIZE_MAINTAINER_ACTION_KIND, computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, authorizeRecord.lifecycleEventHash, candidate.evidenceHash,
    )),
    candidate.maintainerId, candidate.evidenceHash,
  );
  const activateRecord = simulator.getMaintainerMembership(candidate.maintainerId);
  simulator.activateMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    sign(ACTIVATE_MAINTAINER_ACTION_KIND, computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, activateRecord.lifecycleEventHash, candidate.evidenceHash,
    )),
    candidate.maintainerId, candidate.evidenceHash,
  );
};

const expectSignedEvidenceMismatch = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  actionKind: Uint8Array,
  payloadHash: Uint8Array,
  invoke: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) => void,
  diagnostic: RegExp,
): void => {
  const signature = signFixtureDeploymentBoundActionFromSeed(registry.simulator,
    registry.bootstrapMaintainer.seed,
    registry.registryId,
    registry.simulator.getLedger().governancePolicyCommitment,
    actionKind,
    payloadHash,
    registry.simulator.getLedger().governanceActionCount,
  );
  expect(() => invoke(signature)).toThrow(diagnostic);
};

const createEpochCommitmentFixture = (label: string, policyRoot: Uint8Array) => ({
  epochId: labelToBytes32(`epoch:${label}`),
  stateRoot: labelToBytes32(`state-root:${label}`),
  eventRoot: labelToBytes32(`event-root:${label}`),
  policyRoot,
  validFromSequence: 1n,
  validUntilSequence: 61n,
});

describe("trust registry contract", () => {
  it("keeps distinct long and multibyte fixture labels distinct", () => {
    const shared = "evidence:verifier:application:".padEnd(32, "x");
    const proposal = labelToBytes32(`${shared}propose`);
    const authorization = labelToBytes32(`${shared}authorize`);
    const activation = labelToBytes32(`${shared}activate`);
    expect(Buffer.from(proposal)).not.toEqual(Buffer.from(authorization));
    expect(Buffer.from(proposal)).not.toEqual(Buffer.from(activation));
    expect(Buffer.from(authorization)).not.toEqual(Buffer.from(activation));
    expect(Buffer.from(labelToBytes32("é".repeat(17)))).not.toEqual(Buffer.from(labelToBytes32("é".repeat(16) + "a")));
    expect(Buffer.from(labelToBytes32("short"))).toEqual(Buffer.concat([Buffer.from("short"), Buffer.alloc(27)]));
    expect(() => labelToBytes32("short\0")).toThrow(/NUL bytes/);
  });

  it("binds action payload hashes to deployment and policy commitments", () => {
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const address = new Uint8Array(32).fill(9);
    const payload = labelToBytes32("action:payload");
    const bound = pureCircuits.deploymentBoundActionPayloadHash(
      FIXTURE_NETWORK_ID_COMMITMENT, address, policyV1, payload,
    );

    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(pureCircuits.deploymentBoundActionPayloadHash(
        FIXTURE_NETWORK_ID_COMMITMENT, address, policyV2, payload,
      )).toString("hex"),
    );
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(pureCircuits.deploymentBoundActionPayloadHash(
        FIXTURE_NETWORK_ID_COMMITMENT, address, policyV1, labelToBytes32("other"),
      )).toString("hex"),
    );
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(pureCircuits.deploymentBoundActionPayloadHash(
        FIXTURE_NETWORK_ID_COMMITMENT, new Uint8Array(32).fill(10), policyV1, payload,
      )).toString("hex"),
    );
    expect(() => pureCircuits.deploymentBoundActionPayloadHash(
      FIXTURE_NETWORK_ID_COMMITMENT, address, new Uint8Array(32), payload,
    )).toThrow(
      /policy commitment must be set/i,
    );
    expect(() => pureCircuits.deploymentBoundActionPayloadHash(
      new Uint8Array(32), address, policyV1, payload,
    )).toThrow(
      /network id commitment must be set/i,
    );
  });

  it("signs a deployment-bound action digest under one explicit policy snapshot", () => {
    const maintainer = createMaintainerFixture("policy-bound", 19);
    const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
    const registryId = labelToBytes32("registry:policy-bound");
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const actionKind = encodeCompactActionKind("tr:issuer:propose");
    const payload = labelToBytes32("issuer:proposal:payload");
    const contractAddress = new Uint8Array(32).fill(9);
    const signature = signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      registryId,
      FIXTURE_NETWORK_ID_COMMITMENT,
      contractAddress,
      policyV1,
      actionKind,
      payload,
      3n,
    );

    expect(computeDeploymentBoundMaintainerActionDigest(
      registryId, FIXTURE_NETWORK_ID_COMMITMENT, contractAddress,
      policyV1, actionKind, payload, 3n,
    )).toHaveLength(4);
    expect(verifyDeploymentBoundMaintainerAction(
      publicKey, registryId, FIXTURE_NETWORK_ID_COMMITMENT, contractAddress,
      policyV1, actionKind, payload, 3n, signature,
    )).toBe(true);
    expect(verifyDeploymentBoundMaintainerAction(
      publicKey, registryId, FIXTURE_NETWORK_ID_COMMITMENT, contractAddress,
      policyV2, actionKind, payload, 3n, signature,
    )).toBe(false);
  });

  it("accepts valid threshold rules and rejects invalid ones", () => {
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 2n)).not.toThrow();
    expect(() =>
      pureCircuits.assertValidMaintainerThresholdPolicy(3n, 2n, 1n, 1n),
    ).not.toThrow();
    expect(() =>
      pureCircuits.assertValidMaintainerThresholdPolicy(1n, 1n, 1n, 1n),
    ).not.toThrow();
    for (const thresholds of [[2n, 1n, 1n], [1n, 2n, 1n], [1n, 1n, 2n]]) {
      expect(() => pureCircuits.assertValidMaintainerThresholdPolicy(
        2n, thresholds[0]!, thresholds[1]!, thresholds[2]!,
      )).toThrow(/non-conflicted removal quorum/i);
    }
    expect(() =>
      pureCircuits.assertValidMaintainerThresholdPolicy(3n, 3n, 2n, 2n),
    ).toThrow(/non-conflicted removal quorum/i);
    expect(() => pureCircuits.assertValidMaintainerThreshold(0n, 1n)).toThrow(
      /at least 1/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 4n)).toThrow(
      /may not exceed/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(8n, 8n)).toThrow(
      /supported signer-set capacity/i,
    );
    expect(() =>
      pureCircuits.assertSingleSignatureMaintainerThreshold(3n, 2n),
    ).toThrow(/requires threshold 1/i);
  });

  it("records a network-bound initialization event before a contract address exists", () => {
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 7);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    const bootstrap = {
      registryId,
      networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
      registryDidCommitment,
      governancePolicyCommitment,
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    };
    const simulator = new TrustRegistrySimulator(bootstrap);

    const state = simulator.getLedger();
    const maintainer = state.maintainerRecords.lookup(bootstrapMaintainer.keyId);

    expect(state.initialized).toBe(true);
    expect(state.contractVersion).toBe(1n);
    expect(Buffer.from(state.registryId)).toEqual(Buffer.from(registryId));
    expect(Buffer.from(state.registryDidCommitment)).toEqual(
      Buffer.from(registryDidCommitment),
    );
    expect(Buffer.from(state.governancePolicyCommitment)).toEqual(
      Buffer.from(governancePolicyCommitment),
    );
    expect(state.maintainerThreshold).toEqual(1n);
    expect(state.emergencyMaintainerThreshold).toEqual(1n);
    expect(state.archivalMaintainerThreshold).toEqual(1n);
    expect(state.activeMaintainerCount).toEqual(1n);
    expect(state.governanceActionCount).toEqual(1n);
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    const sameNetwork = new TrustRegistrySimulator(bootstrap);
    const otherNetwork = new TrustRegistrySimulator({
      ...bootstrap,
      networkIdCommitment: labelToBytes32("network:other"),
    });
    expect(encodeContractAddress(sameNetwork.contractAddress)).not.toEqual(
      encodeContractAddress(simulator.contractAddress),
    );
    expect(sameNetwork.getLedger().lastGovernanceEventHash).toEqual(state.lastGovernanceEventHash);
    expect(otherNetwork.getLedger().lastGovernanceEventHash).not.toEqual(state.lastGovernanceEventHash);
    expect(maintainer.status).toEqual(MaintainerStatus.active);
    expect(Buffer.from(maintainer.keyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects invalid deployment bootstrap inputs and exposes no first-call initializer", () => {
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 9);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const bootstrap = {
      registryId: labelToBytes32("registry:kanon"),
      networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
      registryDidCommitment: labelToBytes32("did:midnight:registry"),
      governancePolicyCommitment: labelToBytes32("policy:kanon:v1"),
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    };

    expect(() =>
      new TrustRegistrySimulator({ ...bootstrap, registryId: new Uint8Array(32) }),
    ).toThrow(/Registry id must be set/);

    expect(() =>
      new TrustRegistrySimulator({ ...bootstrap, networkIdCommitment: new Uint8Array(32) }),
    ).toThrow(/Deployment network id commitment must be set/);

    expect(() =>
      new TrustRegistrySimulator({ ...bootstrap, governancePolicyCommitment: new Uint8Array(32) }),
    ).toThrow(/Governance policy commitment must be set/);

    expect(() =>
      new TrustRegistrySimulator({ ...bootstrap, maintainerThreshold: 0n }),
    ).toThrow(/threshold must be at least 1/i);

    expect(() =>
      new TrustRegistrySimulator({ ...bootstrap, maintainerThreshold: 2n }),
    ).toThrow(/may not exceed active maintainer count/i);

    expect(() =>
      new TrustRegistrySimulator({
        ...bootstrap,
        maintainerPublicKey: { x: 0n, y: 1n },
      }),
    ).toThrow(/signer point must not be identity/i);

    const lowOrderKey = {
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    };
    expect(() => new TrustRegistrySimulator({
      ...bootstrap,
      maintainerPublicKey: lowOrderKey,
    })).toThrow();

    expect(() => pureCircuits.createMaintainerMembershipPayloadHash(
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      { x: 0n, y: 1n },
      labelToBytes32("policy:maintainer"),
      labelToBytes32("trust:level"),
      labelToBytes32("evidence:hash"),
    )).toThrow(/signer point must not be identity/i);

    const simulator = new TrustRegistrySimulator(bootstrap);
    expect(simulator.getLedger().initialized).toBe(true);
    expect(simulator.getLedger().deploymentNetworkIdCommitment).toEqual(bootstrap.networkIdCommitment);
    expect(simulator.contract.impureCircuits).not.toHaveProperty("initializeRegistry");
  });

  it("does not let an unauthorized first caller replace constructor bootstrap state", () => {
    const registry = createInitializedRegistryFixture(10);
    const { simulator, registryId, bootstrapMaintainer } = registry;
    const original = simulator.getLedger();
    const attacker = createMaintainerFixture("first-caller-attacker", 11);
    const payloadHash = labelToBytes32("attacker:first-action");
    const attackerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      attacker.seed,
      registryId,
      original.governancePolicyCommitment,
      GENERIC_AUDIT_ACTION_KIND,
      payloadHash,
      original.governanceActionCount,
    );

    expect(() => simulator.authorizeMaintainerAuditEvent(
      attacker.keyId,
      deriveJubjubPublicKeyFromSeed(attacker.seed),
      attackerSignature,
      payloadHash,
    )).toThrow(/not registered/i);
    const after = simulator.getLedger();
    expect(after.governanceActionCount).toBe(1n);
    expect(after.registryId).toEqual(registryId);
    expect(after.lastAuthorizedMaintainerKeyId).toEqual(bootstrapMaintainer.keyId);
    expect(simulator.contract.impureCircuits).not.toHaveProperty("initializeRegistry");
  });

  it("invalidates an unsubmitted proposal signature after another governed action advances the sequence", () => {
    const registry = createInitializedRegistryFixture(71);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuer = createIssuerAuthorizationFixture("recovery-sequence");
    const verifier = registerIssuerEvidenceVerifier(registry);
    const proposal = issuerProposalProof(registry, issuer, verifier);
    const reservedSequence = simulator.getLedger().governanceActionCount;
    const reservedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proposal.payloadHash, reservedSequence,
    );

    const auditPayload = labelToBytes32("recovery:advance-sequence");
    const auditSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      GENERIC_AUDIT_ACTION_KIND, auditPayload, reservedSequence,
    );
    simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId, bootstrapPublicKey, auditSignature, auditPayload,
    );
    expect(simulator.getLedger().governanceActionCount).toBe(reservedSequence + 1n);
    expect(simulator.getLedger().issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(false);

    const propose = (signature: typeof reservedSignature) => simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
      issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
      issuer.trustLevel, issuer.evidenceHash, proposal.verifierAuthorizationId,
      proposal.verifierKeyIdCommitment, proposal.evidenceSignature,
    );
    expect(() => propose(reservedSignature)).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().governanceActionCount).toBe(reservedSequence + 1n);
    expect(simulator.getLedger().issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(false);

    const freshSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proposal.payloadHash, reservedSequence + 1n,
    );
    propose(freshSignature);
    expect(simulator.getLedger().issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(true);
  });

  it("governs maintainer membership through proposal, approval, activation, suspension, revocation, and archival", () => {
    const registry = createInitializedRegistryFixture(11);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const candidate = createMaintainerMembershipFixture("governed", 12);
    const proposalProof = maintainerProposalProof(registry, candidate);

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeActionSequence,
    );

    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      candidate.maintainerId,
      candidate.maintainerDidCommitment,
      candidate.keyId,
      candidate.publicKey,
      candidate.policyId,
      candidate.trustLevel,
      candidate.evidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const proposedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(proposedMembership.status).toEqual(AuthorizationStatus.proposed);

    const substitutedEvidence = labelToBytes32("evidence:governed:authorize:substituted");
    expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        proposedMembership.lifecycleEventHash,
        substitutedEvidence,
      ),
      (signature) => simulator.authorizeMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        candidate.maintainerId,
        substitutedEvidence,
      ),
      /maintainer authorization evidence must match the proposed application/i,
    );

    const authorizeEvidenceHash = candidate.evidenceHash;
    const authorizeActionSequence = simulator.getLedger().governanceActionCount;
    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        proposedMembership.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      authorizeActionSequence,
    );

    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      candidate.maintainerId,
      authorizeEvidenceHash,
    );

    const authorizedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(authorizedMembership.status).toEqual(AuthorizationStatus.authorized);

    const substitutedActivationEvidence = labelToBytes32("evidence:governed:activate:substituted");
    expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        authorizedMembership.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      (signature) => simulator.activateMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        candidate.maintainerId,
        substitutedActivationEvidence,
      ),
      /maintainer activation evidence must match the proposed application/i,
    );

    const activateEvidenceHash = candidate.evidenceHash;
    const activateActionSequence = simulator.getLedger().governanceActionCount;
    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        authorizedMembership.lifecycleEventHash,
        activateEvidenceHash,
      ),
      activateActionSequence,
    );

    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      candidate.maintainerId,
      activateEvidenceHash,
    );

    const activeMembership = simulator.getCurrentMaintainerMembership(
      candidate.maintainerDidCommitment,
    );
    const activeMaintainer = simulator.getLedger().maintainerRecords.lookup(
      candidate.keyId,
    );
    expect(activeMembership.status).toEqual(AuthorizationStatus.active);
    expect(activeMaintainer.status).toEqual(MaintainerStatus.active);
    expect(simulator.getLedger().activeMaintainerCount).toEqual(2n);

    const allMemberPolicy = labelToBytes32("policy:recovery:two-of-two");
    const allMemberPolicySequence = simulator.getLedger().governanceActionCount;
    const allMemberPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        allMemberPolicy, 2n, 2n, 2n, 2n,
      ), allMemberPolicySequence,
    );
    expect(() => simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey, allMemberPolicySignature,
      allMemberPolicy, 2n, 2n, 2n, 2n,
    )).toThrow(/non-conflicted removal quorum/i);
    expect(simulator.getLedger().governanceActionCount).toBe(allMemberPolicySequence);

    const suspendEvidenceHash = labelToBytes32("evidence:governed:suspend");
    const suspendActionSequence = simulator.getLedger().governanceActionCount;
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        activeMembership.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );

    const selfRemovalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      candidate.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        activeMembership.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );
    expect(() => simulator.suspendMaintainerMembership(
      candidate.keyId,
      candidate.publicKey,
      selfRemovalSignature,
      candidate.maintainerId,
      suspendEvidenceHash,
    )).toThrow(/own DID/i);
    expect(simulator.getLedger().governanceActionCount).toBe(suspendActionSequence);

    simulator.suspendMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      candidate.maintainerId,
      suspendEvidenceHash,
    );

    const suspendedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(suspendedMembership.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeMaintainerCount).toEqual(1n);

    const revokeEvidenceHash = labelToBytes32("evidence:governed:revoke");
    const revokeActionSequence = simulator.getLedger().governanceActionCount;
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        suspendedMembership.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      revokeActionSequence,
    );

    simulator.revokeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      candidate.maintainerId,
      revokeEvidenceHash,
    );

    const revokedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(revokedMembership.status).toEqual(AuthorizationStatus.revoked);
    expect(
      simulator.getLedger().maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:governed:archive");
    const archiveActionSequence = simulator.getLedger().governanceActionCount;
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        revokedMembership.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      archiveActionSequence,
    );

    simulator.archiveMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      candidate.maintainerId,
      archiveEvidenceHash,
    );

    const archivedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(archivedMembership.status).toEqual(AuthorizationStatus.archived);
    expect(
      simulator.getLedger().maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.archived);
  });

  it("rejects an unregistered or cross-role evidence signature on maintainer enrollment", () => {
    const registry = createInitializedRegistryFixture(62);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("signed-candidate", 63);
    const proof = maintainerProposalProof(registry, candidate);
    const sign = () => signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, simulator.getLedger().governanceActionCount,
    );
    const propose = (keyId: Uint8Array, evidenceSignature: typeof proof.evidenceSignature) =>
      simulator.proposeMaintainerMembership(
        bootstrapMaintainer.keyId, bootstrapPublicKey, sign(),
        candidate.maintainerId, candidate.maintainerDidCommitment,
        candidate.keyId, candidate.publicKey, candidate.policyId,
        candidate.trustLevel, candidate.evidenceHash,
        proof.verifierAuthorizationId, keyId, evidenceSignature,
      );
    expect(() => simulator.getMaintainerProposalEvidence(candidate.maintainerId))
      .toThrow(/not registered/i);
    expect(() => propose(labelToBytes32("wrong-evidence-verifier-key"), proof.evidenceSignature))
      .toThrow(/key id does not match/i);
    expect(() => propose(proof.verifierKeyIdCommitment,
      signAuditorProposalEvidenceFromSeed(
        new Uint8Array(32).fill(97), registryId,
        FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
        proof.verifierKeyIdCommitment, proof.payloadHash,
      ))).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().maintainerMembershipCount).toBe(1n);
    const eventHash = propose(proof.verifierKeyIdCommitment, proof.evidenceSignature);
    const evidence = simulator.getMaintainerProposalEvidence(candidate.maintainerId);
    expect(evidence.evidenceCommitment).toEqual(candidate.evidenceHash);
    expect(evidence.evidenceVerifierKeyIdCommitment).toEqual(proof.verifierKeyIdCommitment);
    expect(evidence.proposalGovernanceEventHash).toEqual(eventHash);
    expect(() => propose(proof.verifierKeyIdCommitment, proof.evidenceSignature))
      .toThrow(/already exists/i);
  });

  it("rejects a nonidentity low-order maintainer key before it can join quorum", () => {
    const registry = createInitializedRegistryFixture(164);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("low-order-candidate", 165);
    candidate.publicKey = {
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    };
    const proof = maintainerProposalProof(registry, candidate);
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      candidate.maintainerId, candidate.maintainerDidCommitment,
      candidate.keyId, candidate.publicKey, candidate.policyId,
      candidate.trustLevel, candidate.evidenceHash,
      proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
    )).toThrow();
    expect(() => simulator.getMaintainerMembership(candidate.maintainerId)).toThrow();
  });

  it("rejects maintainer approval after its proposal evidence policy is superseded", () => {
    const registry = createInitializedRegistryFixture(64);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("stale-governance", 65);
    const proof = maintainerProposalProof(registry, candidate);
    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, simulator.getLedger().governanceActionCount,
      ),
      candidate.maintainerId, candidate.maintainerDidCommitment,
      candidate.keyId, candidate.publicKey, candidate.policyId,
      candidate.trustLevel, candidate.evidenceHash,
      proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    );
    const proposalEvent = simulator.getMaintainerProposalEvidence(candidate.maintainerId).proposalGovernanceEventHash;
    const oldPolicy = simulator.getLedger().governancePolicyCommitment;
    const newPolicy = labelToBytes32("policy:maintainer:evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      oldPolicy, newPolicy, 2n, 1n, 1n, 1n,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, oldPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyHash,
        simulator.getLedger().governanceActionCount,
      ),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    const record = simulator.getMaintainerMembership(candidate.maintainerId);
    const approvalHash = computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, record.lifecycleEventHash, candidate.evidenceHash,
    );
    expect(() => simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, newPolicy, AUTHORIZE_MAINTAINER_ACTION_KIND,
        approvalHash, simulator.getLedger().governanceActionCount,
      ),
      candidate.maintainerId, candidate.evidenceHash,
    )).toThrow(/proposal evidence policy is not current/i);
    expect(simulator.getMaintainerMembership(candidate.maintainerId).status).toBe(AuthorizationStatus.proposed);
    expect(simulator.getMaintainerProposalEvidence(candidate.maintainerId).proposalGovernanceEventHash)
      .toEqual(proposalEvent);
  });

  it("rejects duplicate live maintainer identity enrollment and self-voted deactivation", () => {
    const registry = createInitializedRegistryFixture(13);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const selfCandidate = createMaintainerMembershipFixture("self", 14);
    selfCandidate.maintainerDidCommitment = bootstrapMaintainer.didCommitment;
    const proposalProof = maintainerProposalProof(registry, selfCandidate);

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeActionSequence,
    );

    expect(() =>
      simulator.proposeMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposeSignature,
        selfCandidate.maintainerId,
        selfCandidate.maintainerDidCommitment,
        selfCandidate.keyId,
        selfCandidate.publicKey,
        selfCandidate.policyId,
        selfCandidate.trustLevel,
        selfCandidate.evidenceHash,
        proposalProof.verifierAuthorizationId,
        proposalProof.verifierKeyIdCommitment,
        proposalProof.evidenceSignature,
      ),
    ).toThrow(/already has a live membership/i);

    const selfActions = [
      {
        kind: SUSPEND_MAINTAINER_ACTION_KIND,
        invoke: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          simulator.suspendMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          ),
      },
      {
        kind: REVOKE_MAINTAINER_ACTION_KIND,
        invoke: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          simulator.revokeMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          ),
      },
      {
        kind: ARCHIVE_MAINTAINER_ACTION_KIND,
        invoke: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          simulator.archiveMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          ),
      },
    ];
    for (const action of selfActions) {
      const sequence = simulator.getLedger().governanceActionCount;
      const evidenceHash = labelToBytes32(`evidence:self-removal:${sequence}`);
      const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        simulator.getLedger().governancePolicyCommitment,
        action.kind,
        computeUpdateMaintainerMembershipPayloadHash(
          bootstrapMaintainer.maintainerId,
          simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId).lifecycleEventHash,
          evidenceHash,
        ),
        sequence,
      );
      expect(() => action.invoke(signature, evidenceHash)).toThrow(/own DID/i);
      expect(simulator.getLedger().governanceActionCount).toBe(sequence);
      expect(simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId).status)
        .toBe(AuthorizationStatus.active);
    }
  });

  it.each(["revoke", "archive"] as const)(
    "excludes an active maintainer from their own %s quorum",
    (action) => {
      const registry = createInitializedRegistryFixture(73);
      const { simulator, registryId } = registry;
      const target = createMaintainerMembershipFixture(`self-${action}`, 74);
      activateAdditionalMaintainer(registry, target);
      const kind = action === "revoke"
        ? REVOKE_MAINTAINER_ACTION_KIND : ARCHIVE_MAINTAINER_ACTION_KIND;
      const evidenceHash = labelToBytes32(`evidence:self-${action}`);
      const before = simulator.getLedger().governanceActionCount;
      const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
        target.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        kind,
        computeUpdateMaintainerMembershipPayloadHash(
          target.maintainerId,
          simulator.getMaintainerMembership(target.maintainerId).lifecycleEventHash,
          evidenceHash,
        ),
        before,
      );
      expect(() => {
        if (action === "revoke") {
          simulator.revokeMaintainerMembership(
            target.keyId, target.publicKey, signature, target.maintainerId, evidenceHash,
          );
        } else {
          simulator.archiveMaintainerMembership(
            target.keyId, target.publicKey, signature, target.maintainerId, evidenceHash,
          );
        }
      }).toThrow(/own DID/i);
      expect(simulator.getLedger().governanceActionCount).toBe(before);
      expect(simulator.getMaintainerMembership(target.maintainerId).status)
        .toBe(AuthorizationStatus.active);
    },
  );

  it("atomically reduces policy and removes a target under the old 2-of-3 quorum", () => {
    const registry = createInitializedRegistryFixture(75);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const second = createMaintainerMembershipFixture("recovery-second", 76);
    const target = createMaintainerMembershipFixture("recovery-target", 77);
    activateAdditionalMaintainer(registry, second);
    activateAdditionalMaintainer(registry, target);

    const twoOfThree = labelToBytes32("policy:recovery:two-of-three");
    const firstPolicy = simulator.getLedger().governancePolicyCommitment;
    const policySequence = simulator.getLedger().governanceActionCount;
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, firstPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
        computeUpdateMaintainerThresholdPolicyPayloadHash(
          firstPolicy, twoOfThree, 2n, 2n, 2n, 2n,
        ), policySequence,
      ),
      twoOfThree, 2n, 2n, 2n, 2n,
    );

    const evidenceHash = labelToBytes32("evidence:recovery:remove-target");
    const removalPayload = computeUpdateMaintainerMembershipPayloadHash(
      target.maintainerId,
      simulator.getMaintainerMembership(target.maintainerId).lifecycleEventHash,
      evidenceHash,
    );
    const removalSequence = simulator.getLedger().governanceActionCount;
    const removalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfThree,
      SUSPEND_MAINTAINER_ACTION_KIND, removalPayload, removalSequence,
    );
    const coSigner = createMaintainerCoAuthorizer(
      second, simulator, registryId, SUSPEND_MAINTAINER_ACTION_KIND,
      removalPayload, removalSequence,
    );
    expect(() => simulator.suspendMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, removalSignature,
      target.maintainerId, evidenceHash, [coSigner],
    )).toThrow(/non-conflicted removal quorum/i);
    expect(simulator.getLedger().governanceActionCount).toBe(removalSequence);
    expect(simulator.getMaintainerMembership(target.maintainerId).status)
      .toBe(AuthorizationStatus.active);

    const oneOfTwo = labelToBytes32("policy:recovery:one-of-two");
    const recoveryPayload = computeRecoverMaintainerMembershipPayloadHash(
      twoOfThree, oneOfTwo, 3n, 1n, 1n, 1n,
      target.maintainerId,
      simulator.getMaintainerMembership(target.maintainerId).lifecycleEventHash,
      evidenceHash,
    );
    const recoverySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfThree,
      RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    const recoveryCoSigner = createMaintainerCoAuthorizer(
      second, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    const targetCoSigner = createMaintainerCoAuthorizer(
      target, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [targetCoSigner],
    )).toThrow(/own DID/u);
    expect(simulator.getLedger().governanceActionCount).toBe(removalSequence);
    expect(simulator.getLedger().governancePolicyCommitment).toEqual(twoOfThree);
    expect(simulator.getMaintainerMembership(target.maintainerId).status)
      .toBe(AuthorizationStatus.active);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
    )).toThrow(/signer count must satisfy/u);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 2n, 2n, 2n,
      [recoveryCoSigner],
    )).toThrow(/non-conflicted removal quorum/u);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 4n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )).toThrow(/Policy version must increase by one/u);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, twoOfThree, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )).toThrow(/must not reuse a historical snapshot/u);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, labelToBytes32("policy:recovery:tampered"),
      3n, 1n, 1n, 1n, [recoveryCoSigner],
    )).toThrow(/invalid jubjub schnorr signature/iu);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, labelToBytes32("evidence:recovery:tampered"),
      oneOfTwo, 3n, 1n, 1n, 1n, [recoveryCoSigner],
    )).toThrow(/invalid jubjub schnorr signature/iu);
    expect(simulator.getLedger().governanceActionCount).toBe(removalSequence);

    const recoveryEvent = simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    );
    expect(simulator.getLedger().governancePolicyCommitmentsByVersion.lookup(2n))
      .toEqual(twoOfThree);
    expect(simulator.getLedger().lastGovernanceEventHash).toEqual(recoveryEvent);
    expect(simulator.getLedger().activeMaintainerCount).toBe(2n);
    expect(simulator.getLedger().emergencyMaintainerThreshold).toBe(1n);
    expect(simulator.getLedger().governancePolicyCommitment).toEqual(oneOfTwo);
    expect(simulator.getMaintainerMembership(target.maintainerId).lifecycleEventHash)
      .toEqual(recoveryEvent);
    expect(simulator.getLedger().governanceActionCount).toBe(removalSequence + 1n);
    expect(simulator.getLedger().governancePolicyEffectiveFromByVersion.lookup(3n))
      .toBe(removalSequence + 1n);
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )).toThrow(/must be active to recover/u);
  });
  it("requires the higher old emergency quorum for atomic recovery", () => {
    const registry = createInitializedRegistryFixture(81);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const second = createMaintainerMembershipFixture("recovery-emergency-second", 82);
    const third = createMaintainerMembershipFixture("recovery-emergency-third", 83);
    const target = createMaintainerMembershipFixture("recovery-emergency-target", 84);
    for (const candidate of [second, third, target]) activateAdditionalMaintainer(registry, candidate);
    const initialPolicy = simulator.getLedger().governancePolicyCommitment;
    const twoOfFour = labelToBytes32("policy:recovery:two-of-four");
    const revisionPayload = computeUpdateMaintainerThresholdPolicyPayloadHash(
      initialPolicy, twoOfFour, 2n, 2n, 3n, 2n,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator, bootstrapMaintainer.seed, registryId,
        initialPolicy, UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
        revisionPayload, simulator.getLedger().governanceActionCount),
      twoOfFour, 2n, 2n, 3n, 2n,
    );
    const nextPolicy = labelToBytes32("policy:recovery:two-of-three");
    const evidenceHash = labelToBytes32("evidence:recovery:emergency");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const recoveryPayload = computeRecoverMaintainerMembershipPayloadHash(
      twoOfFour, nextPolicy, 3n, 2n, 2n, 2n,
      target.maintainerId,
      simulator.getMaintainerMembership(target.maintainerId).lifecycleEventHash,
      evidenceHash,
    );
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfFour,
      RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const secondVote = createMaintainerCoAuthorizer(
      second, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const thirdVote = createMaintainerCoAuthorizer(
      third, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const recover = (votes: MaintainerCoAuthorizer[]) => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      target.maintainerId, evidenceHash, nextPolicy, 3n, 2n, 2n, 2n, votes,
    );
    expect(() => recover([secondVote])).toThrow(/signer count must satisfy/u);
    expect(simulator.getLedger().governanceActionCount).toBe(actionSequence);
    expect(simulator.getMaintainerMembership(target.maintainerId).status).toBe(AuthorizationStatus.active);
    recover([secondVote, thirdVote]);
    expect(simulator.getLedger().activeMaintainerCount).toBe(3n);
    expect(simulator.getMaintainerMembership(target.maintainerId).status).toBe(AuthorizationStatus.suspended);
  });
  it("rejects atomic recovery of the last active maintainer", () => {
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = createInitializedRegistryFixture(85);
    const target = simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId);
    const evidenceHash = labelToBytes32("evidence:recovery:last");
    const nextPolicy = labelToBytes32("policy:recovery:last");
    const currentPolicy = simulator.getLedger().governancePolicyCommitment;
    const payload = computeRecoverMaintainerMembershipPayloadHash(
      currentPolicy, nextPolicy, 2n, 1n, 1n, 1n,
      bootstrapMaintainer.maintainerId, target.lifecycleEventHash, evidenceHash,
    );
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, currentPolicy,
      RECOVER_MAINTAINER_ACTION_KIND, payload, simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      bootstrapMaintainer.maintainerId, evidenceHash, nextPolicy, 2n, 1n, 1n, 1n,
    )).toThrow(/last active maintainer/u);
  });
  for (const role of ["issuer", "verifier", "auditor", "recognition"] as const) {
    it(`rejects a maintainer's own ${role} approval without consuming the action sequence`, () => {
      const registry = createInitializedRegistryFixture(31);
      const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
      const sign = (kind: Uint8Array, payloadHash: Uint8Array) =>
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed, registryId,
          simulator.getLedger().governancePolicyCommitment,
          kind, payloadHash, simulator.getLedger().governanceActionCount,
        );
      const scenario = (() => {
        if (role === "issuer") {
          const item = createIssuerAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = issuerProposalProof(registry, item, registerIssuerEvidenceVerifier(registry));
          simulator.proposeIssuerAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, sign(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.resourceType, item.resourceId,
            item.policyId, item.statusPolicyBindingCommitment, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          );
          return {
            kind: AUTHORIZE_ISSUER_ACTION_KIND,
            payloadHash: computeUpdateIssuerAuthorizationPayloadHash(
              item.authorizationId, simulator.getIssuerAuthorization(item.authorizationId).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              simulator.authorizeIssuerAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              ),
            status: () => simulator.getIssuerAuthorization(item.authorizationId).status,
          };
        }
        if (role === "verifier") {
          const item = createVerifierAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = verifierProposalProof(registry, item);
          simulator.proposeVerifierAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, sign(PROPOSE_VERIFIER_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.requestResourceId,
            item.allowedAttributeSetCommitment, item.allowedPredicateSetCommitment,
            item.disclosureLevelCommitment, item.policyId, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          );
          return {
            kind: AUTHORIZE_VERIFIER_ACTION_KIND,
            payloadHash: computeUpdateVerifierAuthorizationPayloadHash(
              item.authorizationId, simulator.getVerifierAuthorization(item.authorizationId).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              simulator.authorizeVerifierAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              ),
            status: () => simulator.getVerifierAuthorization(item.authorizationId).status,
          };
        }
        if (role === "auditor") {
          const item = createAuditorAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = auditorProposalProof(registry, item);
          simulator.proposeAuditorAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, sign(PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.requestResourceId,
            item.allowedAttributeSetCommitment, item.allowedPredicateSetCommitment,
            item.disclosureLevelCommitment, item.policyId, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          );
          return {
            kind: AUTHORIZE_AUDITOR_ACTION_KIND,
            payloadHash: computeUpdateAuditorAuthorizationPayloadHash(
              item.authorizationId, simulator.getAuditorAuthorization(item.authorizationId).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              simulator.authorizeAuditorAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              ),
            status: () => simulator.getAuditorAuthorization(item.authorizationId).status,
          };
        }
        const item = createRecognitionFixture("self-vote");
        item.recognizedAuthorityDidCommitment = bootstrapMaintainer.didCommitment;
        const proof = recognitionProposalProof(registry, item, item.evidenceHash);
        simulator.proposeRecognition(
          bootstrapMaintainer.keyId, bootstrapPublicKey, sign(PROPOSE_RECOGNITION_ACTION_KIND, proof.payloadHash),
          item.recognitionId, item.recognizedAuthorityDidCommitment, item.recognizedRegistryId,
          item.scopeResourceType, item.scopeResourceId, item.policyId, item.trustLevel, item.evidenceHash,
          proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
        );
        return {
          kind: AUTHORIZE_RECOGNITION_ACTION_KIND,
          payloadHash: computeUpdateRecognitionPayloadHash(
            item.recognitionId, simulator.getRecognition(item.recognitionId).lifecycleEventHash,
            item.evidenceHash,
          ),
          authorize: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
            simulator.authorizeRecognition(
              bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
              item.recognitionId, item.evidenceHash,
            ),
          status: () => simulator.getRecognition(item.recognitionId).status,
        };
      })();
      const sequence = simulator.getLedger().governanceActionCount;
      expect(() => scenario.authorize(sign(scenario.kind, scenario.payloadHash))).toThrow(/own DID/i);
      expect(simulator.getLedger().governanceActionCount).toBe(sequence);
      expect(scenario.status()).toBe(AuthorizationStatus.proposed);
    });
  }

  it("records a signed generic audit event without a lifecycle transition", () => {
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 3);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    const simulator = new TrustRegistrySimulator({
      registryId,
      networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
      registryDidCommitment,
      governancePolicyCommitment,
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    });

    const actionKind = GENERIC_AUDIT_ACTION_KIND;
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyFixtureDeploymentBoundAction(simulator,
        bootstrapPublicKey,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        actionKind,
        actionPayloadHash,
        actionSequence,
        signature,
      ),
    ).toBe(true);

    const lifecycleSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      actionPayloadHash,
      actionSequence,
    );
    expect(() => simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      lifecycleSignature,
      actionPayloadHash,
    )).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().governanceActionCount).toBe(actionSequence);

    const eventHash = simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      actionPayloadHash,
    );
    const state = simulator.getLedger();

    expect(Buffer.from(eventHash)).toEqual(Buffer.from(state.lastGovernanceEventHash));
    expect(Buffer.from(eventHash)).toEqual(Buffer.from(pureCircuits.governanceEventHash(
      registryId,
      FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress),
      governancePolicyCommitment,
      state.lastAuthorizedSignerSetHash,
      actionKind,
      actionPayloadHash,
      actionSequence,
    )));
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    expect(state.governanceActionCount).toEqual(2n);
    expect(state.issuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(state.lastAuthorizedActionKind)).toEqual(
      Buffer.from(actionKind),
    );
    expect(Buffer.from(state.lastAuthorizedActionPayloadHash)).toEqual(
      Buffer.from(actionPayloadHash),
    );
    expect(Buffer.from(state.lastAuthorizedMaintainerKeyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("updates quorum thresholds and enforces scoped multi-maintainer execution", () => {
    const registry = createInitializedRegistryFixture(15);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const secondMaintainer = createMaintainerMembershipFixture("second", 16);
    const proposalProof = maintainerProposalProof(registry, secondMaintainer);

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeMaintainerSequence,
    );
    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeMaintainerSignature,
      secondMaintainer.maintainerId,
      secondMaintainer.maintainerDidCommitment,
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      secondMaintainer.policyId,
      secondMaintainer.trustLevel,
      secondMaintainer.evidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    );

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = simulator.getLedger().governanceActionCount;
    const activateMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    );

    const conflictedEvidenceHash = labelToBytes32("evidence:self:second-signer");
    const conflictedSequence = simulator.getLedger().governanceActionCount;
    const conflictedPayloadHash = computeUpdateMaintainerMembershipPayloadHash(
      bootstrapMaintainer.maintainerId,
      simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId).lifecycleEventHash,
      conflictedEvidenceHash,
    );
    const nonconflictedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      secondMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND, conflictedPayloadHash, conflictedSequence,
    );
    const conflictedCoSigner: MaintainerCoAuthorizer = {
      keyId: bootstrapMaintainer.keyId,
      publicKey: bootstrapPublicKey,
      signature: signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        SUSPEND_MAINTAINER_ACTION_KIND, conflictedPayloadHash, conflictedSequence,
      ),
    };
    expect(() => simulator.suspendMaintainerMembership(
      secondMaintainer.keyId, secondMaintainer.publicKey, nonconflictedSignature,
      bootstrapMaintainer.maintainerId, conflictedEvidenceHash, [conflictedCoSigner],
    )).toThrow(/own DID/i);
    expect(simulator.getLedger().governanceActionCount).toBe(conflictedSequence);

    const selfActivation = createIssuerAuthorizationFixture("self-activation");
    selfActivation.subjectDidCommitment = bootstrapMaintainer.didCommitment;
    const selfActivationProof = issuerProposalProof(
      registry, selfActivation, registerIssuerEvidenceVerifier(registry),
    );
    const signAsSecond = (kind: Uint8Array, payloadHash: Uint8Array) =>
      signFixtureDeploymentBoundActionFromSeed(simulator,
        secondMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        kind, payloadHash, simulator.getLedger().governanceActionCount,
      );
    simulator.proposeIssuerAuthorization(
      secondMaintainer.keyId, secondMaintainer.publicKey,
      signAsSecond(PROPOSE_ISSUER_ACTION_KIND, selfActivationProof.payloadHash),
      selfActivation.authorizationId, selfActivation.subjectDidCommitment,
      selfActivation.resourceType, selfActivation.resourceId, selfActivation.policyId,
      selfActivation.statusPolicyBindingCommitment, selfActivation.trustLevel,
      selfActivation.evidenceHash, selfActivationProof.verifierAuthorizationId,
      selfActivationProof.verifierKeyIdCommitment, selfActivationProof.evidenceSignature,
    );
    const authorizePayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      selfActivation.authorizationId,
      simulator.getIssuerAuthorization(selfActivation.authorizationId).lifecycleEventHash,
      selfActivation.evidenceHash,
    );
    simulator.authorizeIssuerAuthorization(
      secondMaintainer.keyId, secondMaintainer.publicKey,
      signAsSecond(AUTHORIZE_ISSUER_ACTION_KIND, authorizePayloadHash),
      selfActivation.authorizationId, selfActivation.evidenceHash,
    );
    const activatePayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      selfActivation.authorizationId,
      simulator.getIssuerAuthorization(selfActivation.authorizationId).lifecycleEventHash,
      selfActivation.evidenceHash,
    );
    const activateSequence = simulator.getLedger().governanceActionCount;
    expect(() => simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        ACTIVATE_ISSUER_ACTION_KIND, activatePayloadHash, activateSequence,
      ),
      selfActivation.authorizationId, selfActivation.evidenceHash,
    )).toThrow(/own DID/i);
    expect(simulator.getLedger().governanceActionCount).toBe(activateSequence);
    expect(simulator.getIssuerAuthorization(selfActivation.authorizationId).status)
      .toBe(AuthorizationStatus.authorized);

    const thirdMaintainer = createMaintainerMembershipFixture("third", 19);
    activateAdditionalMaintainer(registry, thirdMaintainer);
    expect(simulator.getLedger().activeMaintainerCount).toBe(3n);

    const invalidThresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const invalidThresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        labelToBytes32("policy:kanon:v2"),
        2n,
        4n,
        1n,
        1n,
      ),
      invalidThresholdPolicySequence,
    );
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        invalidThresholdPolicySignature,
        labelToBytes32("policy:kanon:v2"),
        2n,
        4n,
        1n,
        1n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    const thresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const thresholdPolicyPayloadHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      simulator.getLedger().governancePolicyCommitment,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      2n,
    );
    const thresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      thresholdPolicyPayloadHash,
      thresholdPolicySequence,
    );
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("policy:kanon:unsigned"),
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        simulator.getLedger().governancePolicyCommitment,
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/must not reuse/i);
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        new Uint8Array(32),
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/Policy commitment must be set/);
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      2n,
    );

    expect(simulator.getLedger().maintainerThreshold).toEqual(2n);
    expect(simulator.getLedger().emergencyMaintainerThreshold).toEqual(1n);
    expect(simulator.getLedger().archivalMaintainerThreshold).toEqual(2n);
    expect(simulator.getLedger().governancePolicyVersion).toEqual(2n);

    const removalEvidenceHash = labelToBytes32("evidence:nonself:threshold-removal");
    const removalSequence = simulator.getLedger().governanceActionCount;
    const removalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      secondMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        bootstrapMaintainer.maintainerId,
        simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId).lifecycleEventHash,
        removalEvidenceHash,
      ),
      removalSequence,
    );
    expect(() => simulator.suspendMaintainerMembership(
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      removalSignature,
      bootstrapMaintainer.maintainerId,
      removalEvidenceHash,
    )).toThrow(/non-conflicted removal quorum/i);
    expect(simulator.getLedger().governanceActionCount).toBe(removalSequence);
    expect(Buffer.from(simulator.getLedger().governancePolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v2")),
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v1")),
    );
    expect(
      Buffer.from(simulator.getLedger().governancePolicyCommitmentsByVersion.lookup(1n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:kanon:v1")));
    expect(
      Buffer.from(simulator.getLedger().governancePolicyCommitmentsByVersion.lookup(2n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:kanon:v2")));
    expect(simulator.getLedger().governancePolicyEffectiveFromByVersion.lookup(2n)).toEqual(
      thresholdPolicySequence + 1n,
    );

    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("unused-policy-commitment"),
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/version must increase/i);

    const auditPayload = labelToBytes32("quorum:raw-order-rejection");
    const auditSequence = simulator.getLedger().governanceActionCount;
    const auditSigners = [
      { keyId: bootstrapMaintainer.keyId, publicKey: bootstrapPublicKey, seed: bootstrapMaintainer.seed },
      { keyId: secondMaintainer.keyId, publicKey: secondMaintainer.publicKey, seed: secondMaintainer.seed },
    ].sort((left, right) => compareMaintainerKeyIds(left.keyId, right.keyId)).reverse()
      .map(({ keyId, publicKey, seed }) => ({
        keyId,
        publicKey,
        signature: signFixtureDeploymentBoundActionFromSeed(simulator,
          seed, registryId, simulator.getLedger().governancePolicyCommitment,
          GENERIC_AUDIT_ACTION_KIND, auditPayload, auditSequence),
      }));
    const emptySigner = {
      keyId: new Uint8Array(32),
      publicKey: { x: 0n, y: 0n },
      signature: { announcement: { x: 0n, y: 0n }, response: 0n },
    };
    expect(() => simulator.contract.impureCircuits.authorizeMaintainerAuditEvent(
      simulator.circuitContext,
      {
        signerCount: 2n,
        signer1: auditSigners[0]!,
        signer2: auditSigners[1]!,
        signer3: emptySigner,
        signer4: emptySigner,
        signer5: emptySigner,
      },
      auditPayload,
    )).toThrow(/Maintainer signer keys must be sorted/);
    expect(() => simulator.contract.impureCircuits.authorizeMaintainerAuditEvent(
      simulator.circuitContext,
      {
        signerCount: 2n,
        signer1: auditSigners[0]!,
        signer2: auditSigners[0]!,
        signer3: emptySigner,
        signer4: emptySigner,
        signer5: emptySigner,
      },
      auditPayload,
    )).toThrow(/Maintainer signer keys must be sorted/);
    expect(simulator.getLedger().governanceActionCount).toBe(auditSequence);

    const issuer = createIssuerAuthorizationFixture("quorum");
    const proposedEvidenceHash = labelToBytes32("evidence:quorum:issuer:propose");
    const issuerProof = issuerProposalProof(
      registry, { ...issuer, evidenceHash: proposedEvidenceHash },
      registerIssuerEvidenceVerifier(registry, secondMaintainer),
    );
    const proposeIssuerPayloadHash = issuerProof.payloadHash;

    const singleSignerSequence = simulator.getLedger().governanceActionCount;
    const singleSignerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      singleSignerSequence,
    );
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        singleSignerSignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.statusPolicyBindingCommitment,
        issuer.trustLevel,
        proposedEvidenceHash,
        issuerProof.verifierAuthorizationId,
        issuerProof.verifierKeyIdCommitment,
        issuerProof.evidenceSignature,
      ),
    ).toThrow(/must satisfy the action threshold/i);

    const proposeIssuerSequence = simulator.getLedger().governanceActionCount;
    const proposeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const secondIssuerProposer = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const stalePolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      labelToBytes32("policy:kanon:v1"),
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        stalePolicySignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.statusPolicyBindingCommitment,
        issuer.trustLevel,
        proposedEvidenceHash,
        issuerProof.verifierAuthorizationId,
        issuerProof.verifierKeyIdCommitment,
        issuerProof.evidenceSignature,
        [secondIssuerProposer],
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeIssuerSignature,
      issuer.authorizationId,
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceId,
      issuer.policyId,
      issuer.statusPolicyBindingCommitment,
      issuer.trustLevel,
      proposedEvidenceHash,
      issuerProof.verifierAuthorizationId,
      issuerProof.verifierKeyIdCommitment,
      issuerProof.evidenceSignature,
      [secondIssuerProposer],
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v2")),
    );

    const authorizeIssuerEvidenceHash = proposedEvidenceHash;
    const authorizeIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      authorizeIssuerEvidenceHash,
    );
    const authorizeIssuerSequence = simulator.getLedger().governanceActionCount;
    const authorizeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    const secondIssuerAuthorizer = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeIssuerSignature,
      issuer.authorizationId,
      authorizeIssuerEvidenceHash,
      [secondIssuerAuthorizer],
    );

    const activateIssuerEvidenceHash = proposedEvidenceHash;
    const activateIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      activateIssuerEvidenceHash,
    );
    const activateIssuerSequence = simulator.getLedger().governanceActionCount;
    const activateIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    const secondIssuerActivator = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateIssuerSignature,
      issuer.authorizationId,
      activateIssuerEvidenceHash,
      [secondIssuerActivator],
    );

    const suspendedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:suspend",
    );
    const suspendIssuerSequence = simulator.getLedger().governanceActionCount;
    const suspendIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuer.authorizationId,
        simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
        suspendedIssuerEvidenceHash,
      ),
      suspendIssuerSequence,
    );
    simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendIssuerSignature,
      issuer.authorizationId,
      suspendedIssuerEvidenceHash,
    );

    expect(simulator.getIssuerAuthorization(issuer.authorizationId).status).toEqual(
      AuthorizationStatus.suspended,
    );

    const archivedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:archive",
    );
    const archiveIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      archivedIssuerEvidenceHash,
    );
    const archiveIssuerSequence = simulator.getLedger().governanceActionCount;
    const archiveIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    expect(() =>
      simulator.archiveIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        archiveIssuerSignature,
        issuer.authorizationId,
        archivedIssuerEvidenceHash,
      ),
    ).toThrow(/must satisfy the action threshold/i);

    const secondIssuerArchiver = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveIssuerSignature,
      issuer.authorizationId,
      archivedIssuerEvidenceHash,
      [secondIssuerArchiver],
    );

    expect(simulator.getIssuerAuthorization(issuer.authorizationId).status).toEqual(
      AuthorizationStatus.archived,
    );
  }, 20_000);

  it("rejects duplicate maintainer signers before quorum execution", () => {
    const registry = createInitializedRegistryFixture(17);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const secondMaintainer = createMaintainerMembershipFixture("duplicate", 18);
    const proposalProof = maintainerProposalProof(registry, secondMaintainer);

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeMaintainerSequence,
    );
    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeMaintainerSignature,
      secondMaintainer.maintainerId,
      secondMaintainer.maintainerDidCommitment,
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      secondMaintainer.policyId,
      secondMaintainer.trustLevel,
      secondMaintainer.evidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    );

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = simulator.getLedger().governanceActionCount;
    const activateMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    );

    activateAdditionalMaintainer(registry, createMaintainerMembershipFixture("third-duplicate", 20));

    const thresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const thresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        labelToBytes32("policy:kanon:v2"),
        2n,
        2n,
        1n,
        1n,
      ),
      thresholdPolicySequence,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      1n,
    );

    const issuer = createIssuerAuthorizationFixture("duplicate-quorum");
    const proposedEvidenceHash = labelToBytes32(
      "evidence:duplicate:issuer:propose",
    );
    const issuerProof = issuerProposalProof(
      registry, { ...issuer, evidenceHash: proposedEvidenceHash },
      registerIssuerEvidenceVerifier(registry, secondMaintainer),
    );
    const proposeIssuerPayloadHash = issuerProof.payloadHash;
    const proposeIssuerSequence = simulator.getLedger().governanceActionCount;
    const proposeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const duplicateBootstrapAuthorizer: MaintainerCoAuthorizer = {
      keyId: bootstrapMaintainer.keyId,
      publicKey: bootstrapPublicKey,
      signature: signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposeIssuerPayloadHash,
        proposeIssuerSequence,
      ),
    };

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposeIssuerSignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.statusPolicyBindingCommitment,
        issuer.trustLevel,
        proposedEvidenceHash,
        issuerProof.verifierAuthorizationId,
        issuerProof.verifierKeyIdCommitment,
        issuerProof.evidenceSignature,
        [duplicateBootstrapAuthorizer],
      ),
    ).toThrow(/duplicate key ID/u);
    expect(simulator.getLedger().governanceActionCount).toBe(proposeIssuerSequence);
  });

  it("does not count two maintainer IDs controlled by one public key as a quorum", () => {
    const registry = createInitializedRegistryFixture(21);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const duplicateKeyMaintainer = {
      ...createMaintainerMembershipFixture("shared-key", 22),
      publicKey: bootstrapPublicKey,
      seed: bootstrapMaintainer.seed,
    };
    activateAdditionalMaintainer(registry, duplicateKeyMaintainer);
    activateAdditionalMaintainer(registry, createMaintainerMembershipFixture("independent-key", 23));

    const nextPolicy = labelToBytes32("policy:shared-key:v2");
    const policyPayload = computeUpdateMaintainerThresholdPolicyPayloadHash(
      simulator.getLedger().governancePolicyCommitment, nextPolicy, 2n, 2n, 1n, 1n,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyPayload,
        simulator.getLedger().governanceActionCount),
      nextPolicy, 2n, 2n, 1n, 1n,
    );

    const payload = labelToBytes32("audit:shared-maintainer-key");
    const sequence = simulator.getLedger().governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      GENERIC_AUDIT_ACTION_KIND, payload, sequence,
    );
    const duplicateSigner = createMaintainerCoAuthorizer(
      duplicateKeyMaintainer, simulator, registryId, GENERIC_AUDIT_ACTION_KIND,
      payload, sequence,
    );
    expect(() => simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature, payload, [duplicateSigner],
    )).toThrow(/public keys must be distinct/u);
    expect(simulator.getLedger().governanceActionCount).toBe(sequence);
  });

  it("bootstraps before any maintainer action and rejects tampered authorization", () => {
    const registryId = labelToBytes32("registry:kanon");
    const actionKind = GENERIC_AUDIT_ACTION_KIND;
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 5);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const simulator = new TrustRegistrySimulator({
      registryId,
      networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
      registryDidCommitment: labelToBytes32("did:midnight:registry"),
      governancePolicyCommitment: labelToBytes32("policy:kanon:v1"),
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    });
    expect(simulator.getLedger().initialized).toBe(true);

    const actionSequence = simulator.getLedger().governanceActionCount;
    const validSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
    const tamperedSignature = {
      ...validSignature,
      response: validSignature.response + 1n,
    };

    expect(() =>
      simulator.authorizeMaintainerAuditEvent(
        labelToBytes32("maintainer:wrong"),
        bootstrapPublicKey,
        validSignature,
        actionPayloadHash,
      ),
    ).toThrow(/not registered/i);

    expect(() =>
      simulator.authorizeMaintainerAuditEvent(
        bootstrapMaintainer.keyId,
        deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
        validSignature,
        actionPayloadHash,
      ),
    ).toThrow(/does not match the registered key/i);

    expect(() =>
      simulator.authorizeMaintainerAuditEvent(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        actionPayloadHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
  });

  it("creates and queries an active issuer authorization by id and scope", () => {
    const registry = createInitializedRegistryFixture(17);
    const { simulator } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("birth");
    const eventHash = activateIssuerAuthorizationFixture(registry, issuerAuthorization);
    const state = simulator.getLedger();
    const recordById = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const recordByScope = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );

    expect(state.issuerAuthorizationCount).toEqual(1n);
    expect(state.activeIssuerAuthorizationCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(recordById.resourceType).toEqual(
      IssuerResourceType.credentialFamily,
    );
    expect(Buffer.from(recordById.authorizationId)).toEqual(
      Buffer.from(issuerAuthorization.authorizationId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.authorizationId)).toEqual(
      Buffer.from(issuerAuthorization.authorizationId),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).not.toThrow();
  });

  it("requires issuer proposal evidence from the registered active verifier for the exact payload", () => {
    const registry = createInitializedRegistryFixture(18);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuer = createIssuerAuthorizationFixture("evidence-bound");
    const verifier = registerIssuerEvidenceVerifier(registry);
    const proof = issuerProposalProof(registry, issuer, verifier);
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    const propose = (
      fields: IssuerFixture = issuer,
      keyId = proof.verifierKeyIdCommitment,
      evidenceSignature = proof.evidenceSignature,
    ) => simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      fields.authorizationId, fields.subjectDidCommitment, fields.resourceType,
      fields.resourceId, fields.policyId, fields.statusPolicyBindingCommitment,
      fields.trustLevel, fields.evidenceHash,
      proof.verifierAuthorizationId, keyId, evidenceSignature,
    );

    expect(() => propose(issuer, labelToBytes32("verifier:key:wrong")))
      .toThrow(/key id does not match/i);
    expect(() => propose({ ...issuer, subjectDidCommitment: labelToBytes32("did:issuer:altered") }))
      .toThrow(/invalid jubjub schnorr signature/i);
    expect(() => propose({ ...issuer, resourceId: labelToBytes32("resource:altered") }))
      .toThrow(/invalid jubjub schnorr signature/i);
    expect(() => propose({ ...issuer, evidenceHash: labelToBytes32("evidence:altered") }))
      .toThrow(/invalid jubjub schnorr signature/i);
    expect(() => propose(issuer, proof.verifierKeyIdCommitment, {
      ...proof.evidenceSignature, response: 0n,
    })).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().issuerAuthorizationCount).toEqual(0n);

    const suspendPayload = computeUpdateEvidenceVerifierKeyPayloadHash(
      verifier.authorizationId,
      simulator.getEvidenceVerifierKey(verifier.authorizationId).lifecycleEventHash,
      labelToBytes32("verifier:suspended"),
    );
    simulator.suspendEvidenceVerifierKey(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        simulator.getLedger().governancePolicyCommitment,
        SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND, suspendPayload,
        simulator.getLedger().governanceActionCount,
      ),
      verifier.authorizationId, labelToBytes32("verifier:suspended"),
    );
    expect(() => propose()).toThrow(/evidence verifier key is not active/i);
    expect(simulator.getLedger().issuerAuthorizationCount).toEqual(0n);
  });

  it.each(["suspended-key-at-approval", "superseded-policy-at-activation"] as const)(
    "rejects issuer lifecycle transition with %s evidence",
    (scenario) => {
      const registry = createInitializedRegistryFixture(39);
      const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
      const issuer = createIssuerAuthorizationFixture(scenario);
      const verifier = registerIssuerEvidenceVerifier(registry);
      const proof = issuerProposalProof(registry, issuer, verifier);
      const signAction = (kind: Uint8Array, payloadHash: Uint8Array) =>
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed, registryId,
          simulator.getLedger().governancePolicyCommitment,
          kind, payloadHash, simulator.getLedger().governanceActionCount,
        );

      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId, bootstrapPublicKey,
        signAction(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
        issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
        issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
        issuer.trustLevel, issuer.evidenceHash,
        proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
        proof.evidenceSignature,
      );

      const signIssuerTransition = (kind: Uint8Array) => signAction(
        kind,
        computeUpdateIssuerAuthorizationPayloadHash(
          issuer.authorizationId,
          simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
          issuer.evidenceHash,
        ),
      );
      if (scenario === "superseded-policy-at-activation") {
        simulator.authorizeIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          signIssuerTransition(AUTHORIZE_ISSUER_ACTION_KIND),
          issuer.authorizationId, issuer.evidenceHash,
        );
        const nextPolicy = labelToBytes32("policy:issuer:next");
        simulator.updateMaintainerThresholdPolicy(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          signAction(
            UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
            computeUpdateMaintainerThresholdPolicyPayloadHash(
              simulator.getLedger().governancePolicyCommitment,
              nextPolicy, 2n, 1n, 1n, 1n,
            ),
          ),
          nextPolicy, 2n, 1n, 1n, 1n,
        );
      } else {
        const suspendEvidence = labelToBytes32("evidence:verifier:suspend-after-proposal");
        simulator.suspendEvidenceVerifierKey(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          signAction(
            SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
            computeUpdateEvidenceVerifierKeyPayloadHash(
              verifier.authorizationId,
              simulator.getEvidenceVerifierKey(verifier.authorizationId).lifecycleEventHash,
              suspendEvidence,
            ),
          ),
          verifier.authorizationId, suspendEvidence,
        );
      }

      const sequence = simulator.getLedger().governanceActionCount;
      const eventHash = simulator.getLedger().lastGovernanceEventHash;
      const kind = scenario === "superseded-policy-at-activation"
        ? ACTIVATE_ISSUER_ACTION_KIND : AUTHORIZE_ISSUER_ACTION_KIND;
      const signature = signIssuerTransition(kind);
      expect(() => scenario === "superseded-policy-at-activation"
        ? simulator.activateIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
          issuer.authorizationId, issuer.evidenceHash,
        )
        : simulator.authorizeIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
          issuer.authorizationId, issuer.evidenceHash,
        )).toThrow(scenario === "superseded-policy-at-activation"
          ? /proposal evidence policy is not current/i
          : /evidence verifier key is not active/i);
      expect(simulator.getLedger().governanceActionCount).toBe(sequence);
      expect(simulator.getLedger().lastGovernanceEventHash).toEqual(eventHash);
      expect(simulator.getIssuerAuthorization(issuer.authorizationId).status).toEqual(
        scenario === "superseded-policy-at-activation"
          ? AuthorizationStatus.authorized : AuthorizationStatus.proposed,
      );
    },
  );

  it("moves an issuer authorization through proposed, authorized, and active states", () => {
    const registry = createInitializedRegistryFixture(19);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("application");
    const proposalEvidenceHash = labelToBytes32("evidence:application:propose");
    const proposalProof = issuerProposalProof(
      registry, { ...issuerAuthorization, evidenceHash: proposalEvidenceHash },
      registerIssuerEvidenceVerifier(registry),
    );
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposalProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposalSignature,
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        new Uint8Array(32),
        issuerAuthorization.trustLevel,
        proposalEvidenceHash,
        proposalProof.verifierAuthorizationId,
        proposalProof.verifierKeyIdCommitment,
        proposalProof.evidenceSignature,
      ),
    ).toThrow(/issuer status policy binding commitment must be set/i);
    const substitutedPolicyProof = issuerProposalProof(registry, {
      ...issuerAuthorization,
      evidenceHash: proposalEvidenceHash,
      statusPolicyBindingCommitment: labelToBytes32("status-policy:substituted"),
    }, registerIssuerEvidenceVerifier(registry));
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposalSignature,
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        labelToBytes32("status-policy:substituted"),
        issuerAuthorization.trustLevel,
        proposalEvidenceHash,
        proposalProof.verifierAuthorizationId,
        proposalProof.verifierKeyIdCommitment,
        substitutedPolicyProof.evidenceSignature,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
    const proposalEventHash = simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposalSignature,
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.statusPolicyBindingCommitment,
      issuerAuthorization.trustLevel,
      proposalEvidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );
    const proposedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const proposalEvidence = simulator.getIssuerProposalEvidence(
      issuerAuthorization.authorizationId,
    );

    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(Buffer.from(proposalEvidence.evidenceCommitment)).toEqual(
      Buffer.from(proposalEvidenceHash),
    );
    expect(Buffer.from(proposalEvidence.evidenceVerifierAuthorizationId)).toEqual(
      Buffer.from(proposalProof.verifierAuthorizationId),
    );
    expect(Buffer.from(proposalEvidence.evidenceVerifierKeyIdCommitment)).toEqual(
      Buffer.from(proposalProof.verifierKeyIdCommitment),
    );
    expect(proposalEvidence.verifierSignatureResponse).toEqual(
      proposalProof.evidenceSignature.response,
    );
    expect(Buffer.from(proposalEvidence.proposalGovernanceEventHash)).toEqual(
      Buffer.from(proposalEventHash),
    );
    expect(Buffer.from(proposedRecord.statusPolicyBindingCommitment)).toEqual(
      Buffer.from(issuerAuthorization.statusPolicyBindingCommitment),
    );
    expect(proposedRecord.authorizedAtSequence).toEqual(0n);
    expect(proposedRecord.activeFromSequence).toEqual(0n);
    expect(simulator.getLedger().issuerAuthorizationCount).toEqual(1n);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(proposedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(proposalEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const mismatchedEvidenceHash = labelToBytes32("evidence:application:mismatched");
    const mismatchedAuthorizationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        mismatchedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        mismatchedAuthorizationSignature,
        issuerAuthorization.authorizationId,
        mismatchedEvidenceHash,
      ),
    ).toThrow(/must match the proposed application/i);

    const authorizationEvidenceHash = proposalEvidenceHash;
    const authorizationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        authorizationEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    const authorizationEventHash = simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizationSignature,
      issuerAuthorization.authorizationId,
      authorizationEvidenceHash,
    );
    const authorizedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );

    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(Buffer.from(authorizedRecord.statusPolicyBindingCommitment)).toEqual(
      Buffer.from(issuerAuthorization.statusPolicyBindingCommitment),
    );
    expect(authorizedRecord.authorizedAtSequence).toBeGreaterThan(
      proposedRecord.proposedAtSequence,
    );
    expect(authorizedRecord.activeFromSequence).toEqual(0n);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(authorizedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(authorizationEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const substitutedActivationEvidence = labelToBytes32("evidence:application:activate:substituted");
    expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      (signature) => simulator.activateIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        issuerAuthorization.authorizationId,
        substitutedActivationEvidence,
      ),
      /issuer activation evidence must match the proposed application/i,
    );

    const activationEvidenceHash = proposalEvidenceHash;
    const activationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        activationEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    const activationEventHash = simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activationSignature,
      issuerAuthorization.authorizationId,
      activationEvidenceHash,
    );
    const activeRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );

    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(activeRecord.statusPolicyBindingCommitment)).toEqual(
      Buffer.from(issuerAuthorization.statusPolicyBindingCommitment),
    );
    expect(activeRecord.activeFromSequence).toBeGreaterThan(
      authorizedRecord.authorizedAtSequence,
    );
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(1n);
    expect(Buffer.from(activeRecord.lifecycleEventHash)).toEqual(
      Buffer.from(activationEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).not.toThrow();
  });

  it("archives proposed issuer applications and revokes authorized issuer applications before activation", () => {
    const registry = createInitializedRegistryFixture(21);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const archivedProposal = createIssuerAuthorizationFixture("archivable");
    const revocableAuthorization = createIssuerAuthorizationFixture("revocable");
    const verifier = registerIssuerEvidenceVerifier(registry);
    const archivedProof = issuerProposalProof(registry, archivedProposal, verifier);

    const archivedProposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      archivedProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archivedProposalSignature,
      archivedProposal.authorizationId,
      archivedProposal.subjectDidCommitment,
      archivedProposal.resourceType,
      archivedProposal.resourceId,
      archivedProposal.policyId,
      archivedProposal.statusPolicyBindingCommitment,
      archivedProposal.trustLevel,
      archivedProposal.evidenceHash,
      archivedProof.verifierAuthorizationId,
      archivedProof.verifierKeyIdCommitment,
      archivedProof.evidenceSignature,
    );
    const proposedRecord = simulator.getIssuerAuthorization(
      archivedProposal.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:archivable:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        archivedProposal.authorizationId,
        proposedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      archivedProposal.authorizationId,
      archiveEvidenceHash,
    );
    expect(
      simulator.getIssuerAuthorization(archivedProposal.authorizationId).status,
    ).toEqual(AuthorizationStatus.archived);

    const revocableProof = issuerProposalProof(registry, revocableAuthorization, verifier);
    const revocableProposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      revocableProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revocableProposalSignature,
      revocableAuthorization.authorizationId,
      revocableAuthorization.subjectDidCommitment,
      revocableAuthorization.resourceType,
      revocableAuthorization.resourceId,
      revocableAuthorization.policyId,
      revocableAuthorization.statusPolicyBindingCommitment,
      revocableAuthorization.trustLevel,
      revocableAuthorization.evidenceHash,
      revocableProof.verifierAuthorizationId,
      revocableProof.verifierKeyIdCommitment,
      revocableProof.evidenceSignature,
    );
    const revocableProposedRecord = simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    );
    const authorizeEvidenceHash = revocableAuthorization.evidenceHash;
    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        revocableProposedRecord.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      revocableAuthorization.authorizationId,
      authorizeEvidenceHash,
    );
    const authorizedRecord = simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    );
    const revokeEvidenceHash = labelToBytes32("evidence:revocable:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      revocableAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    expect(
      simulator.getIssuerAuthorization(revocableAuthorization.authorizationId)
        .status,
    ).toEqual(AuthorizationStatus.revoked);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("suspends, revokes, and archives issuer authorizations while preserving append-only scope state", () => {
    const registry = createInitializedRegistryFixture(23);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("degree");
    activateIssuerAuthorizationFixture(registry, issuerAuthorization);

    const createdRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:degree:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      issuerAuthorization.authorizationId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:degree:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      issuerAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:degree:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      issuerAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate issuer scope proposals, invalid transitions, tampered signatures, and missing queries", () => {
    const registry = createInitializedRegistryFixture(29);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("license");
    const verifier = registerIssuerEvidenceVerifier(registry);

    expect(() =>
      simulator.getIssuerAuthorization(labelToBytes32("issuer-auth:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentIssuerAuthorization(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/scope is not registered/i);

    const proof = issuerProposalProof(registry, issuerAuthorization, verifier);
    const proposalPayloadHash = proof.payloadHash;
    const tamperedProposalSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposalPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedProposalSignature,
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.statusPolicyBindingCommitment,
        issuerAuthorization.trustLevel,
        issuerAuthorization.evidenceHash,
        proof.verifierAuthorizationId,
        proof.verifierKeyIdCommitment,
        proof.evidenceSignature,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const proposalAuthorizationId = labelToBytes32("issuer-auth:license:proposal");
    const proposalEvidenceHash = labelToBytes32("evidence:license:proposal");
    const proposalProof = issuerProposalProof(
      registry,
      { ...issuerAuthorization, authorizationId: proposalAuthorizationId, evidenceHash: proposalEvidenceHash },
      verifier,
    );
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposalProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposalSignature,
      proposalAuthorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.statusPolicyBindingCommitment,
      issuerAuthorization.trustLevel,
      proposalEvidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const duplicateProof = issuerProposalProof(registry, {
      ...issuerAuthorization,
      authorizationId: labelToBytes32("issuer-auth:license:proposal:duplicate"),
      evidenceHash: labelToBytes32("evidence:license:proposal:duplicate"),
    }, verifier);

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          duplicateProof.payloadHash,
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license:proposal:duplicate"),
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.statusPolicyBindingCommitment,
        issuerAuthorization.trustLevel,
        labelToBytes32("evidence:license:proposal:duplicate"),
        duplicateProof.verifierAuthorizationId,
        duplicateProof.verifierKeyIdCommitment,
        duplicateProof.evidenceSignature,
      ),
    ).toThrow(/live authorization/i);

    expect(() =>
      simulator.activateIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          ACTIVATE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            proposalAuthorizationId,
            simulator.getIssuerAuthorization(proposalAuthorizationId)
              .lifecycleEventHash,
            labelToBytes32("evidence:license:activate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        proposalAuthorizationId,
        labelToBytes32("evidence:license:activate"),
      ),
    ).toThrow(/must be authorized/i);

    const activeIssuerAuthorization = createIssuerAuthorizationFixture("license-active");
    activateIssuerAuthorizationFixture(registry, activeIssuerAuthorization);
    const activeDuplicateProof = issuerProposalProof(registry, {
      ...activeIssuerAuthorization,
      authorizationId: labelToBytes32("issuer-auth:license-active:duplicate"),
      evidenceHash: labelToBytes32("evidence:license-active:duplicate"),
    }, verifier);

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          activeDuplicateProof.payloadHash,
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license-active:duplicate"),
        activeIssuerAuthorization.subjectDidCommitment,
        activeIssuerAuthorization.resourceType,
        activeIssuerAuthorization.resourceId,
        activeIssuerAuthorization.policyId,
        activeIssuerAuthorization.statusPolicyBindingCommitment,
        activeIssuerAuthorization.trustLevel,
        labelToBytes32("evidence:license-active:duplicate"),
        activeDuplicateProof.verifierAuthorizationId,
        activeDuplicateProof.verifierKeyIdCommitment,
        activeDuplicateProof.evidenceSignature,
      ),
    ).toThrow(/live authorization/i);

    expect(() =>
      simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          AUTHORIZE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license-active:authorize"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license-active:authorize"),
      ),
    ).toThrow(/must be proposed/i);

    const createdRecord = simulator.getIssuerAuthorization(
      activeIssuerAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:license:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        activeIssuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      activeIssuerAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active verifier authorization with predicate and disclosure scoped lookups", () => {
    const registry = createInitializedRegistryFixture(31);
    const {
      simulator,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("age-gate");
    const eventHash = activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const state = simulator.getLedger();
    const recordById = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const recordByScope = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );

    expect(state.verifierAuthorizationCount).toEqual(1n);
    expect(state.activeVerifierAuthorizationCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(recordById.authorizationId)).toEqual(
      Buffer.from(verifierAuthorization.authorizationId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.authorizationId)).toEqual(
      Buffer.from(verifierAuthorization.authorizationId),
    );
    expect(() =>
      simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).not.toThrow();
    expect(() =>
      simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        labelToBytes32("pred-set:age-gate:different"),
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/scope is not registered/i);
  });

  it("keeps two full request resources for one verifier and partial request tuple distinct", () => {
    const registry = createInitializedRegistryFixture(32);
    const first = createVerifierAuthorizationFixture("same-profile");
    const second = {
      ...first,
      authorizationId: labelToBytes32("verifier-auth:same-profile:other-purpose"),
      requestResourceId: labelToBytes32("request-resource:same-profile:other-purpose"),
      evidenceHash: labelToBytes32("evidence:same-profile:other-purpose"),
    };
    expect(Buffer.from(second.requestResourceId)).not.toEqual(Buffer.from(first.requestResourceId));
    activateVerifierAuthorizationFixture(registry, first);
    activateVerifierAuthorizationFixture(registry, second);
    expect(registry.simulator.getLedger().activeVerifierAuthorizationCount).toBe(2n);
    for (const authorization of [first, second]) {
      const current = registry.simulator.getCurrentVerifierAuthorization(
        authorization.subjectDidCommitment,
        authorization.requestResourceId,
        authorization.allowedAttributeSetCommitment,
        authorization.allowedPredicateSetCommitment,
        authorization.disclosureLevelCommitment,
      );
      expect(Buffer.from(current.authorizationId)).toEqual(Buffer.from(authorization.authorizationId));
    }
  });

  it("moves a verifier authorization through proposed, authorized, and active states", () => {
    const registry = createInitializedRegistryFixture(35);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("employment-application");
    const proposalEvidenceHash = labelToBytes32("evidence:employment:proposal");
    const proposed = { ...verifierAuthorization, evidenceHash: proposalEvidenceHash };
    const proposalProof = verifierProposalProof(registry, proposed);

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_VERIFIER_ACTION_KIND,
      proposalProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      verifierAuthorization.authorizationId,
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
      verifierAuthorization.policyId,
      verifierAuthorization.trustLevel,
      proposalEvidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const proposedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const substitutedAuthorizationEvidence = labelToBytes32("evidence:employment:authorize:substituted");
    expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        substitutedAuthorizationEvidence,
      ),
      (signature) => simulator.authorizeVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        verifierAuthorization.authorizationId,
        substitutedAuthorizationEvidence,
      ),
      /verifier authorization evidence must match the proposed application/i,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    );

    const authorizedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const substitutedActivationEvidence = labelToBytes32("evidence:employment:activate:substituted");
    expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      (signature) => simulator.activateVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        verifierAuthorization.authorizationId,
        substitutedActivationEvidence,
      ),
      /verifier activation evidence must match the proposed application/i,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    );

    const activeRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(1n);
  });

  it("suspends, revokes, and archives verifier authorizations while preserving scope-sensitive state", () => {
    const registry = createInitializedRegistryFixture(37);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("university");
    activateVerifierAuthorizationFixture(registry, verifierAuthorization);

    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:university:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      verifierAuthorization.authorizationId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);
    expect(() =>
      simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:university:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      verifierAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:university:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate verifier scopes, invalid transitions, tampered signatures, and missing verifier queries", () => {
    const registry = createInitializedRegistryFixture(41);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("passport");

    expect(() =>
      simulator.getVerifierAuthorization(labelToBytes32("verifier-auth:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/scope is not registered/i);

    const proposalProof = verifierProposalProof(registry, verifierAuthorization);
    const tamperedProposeSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        proposalProof.payloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };
    expect(() => simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      tamperedProposeSignature,
      verifierAuthorization.authorizationId,
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
      verifierAuthorization.policyId,
      verifierAuthorization.trustLevel,
      verifierAuthorization.evidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const duplicate = {
      ...verifierAuthorization,
      authorizationId: labelToBytes32("verifier-auth:passport:duplicate"),
      evidenceHash: labelToBytes32("evidence:passport:duplicate"),
    };
    const duplicateProof = verifierProposalProof(registry, duplicate);
    expect(() => simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        duplicateProof.payloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      duplicate.authorizationId,
      duplicate.subjectDidCommitment,
      duplicate.requestResourceId,
      duplicate.allowedAttributeSetCommitment,
      duplicate.allowedPredicateSetCommitment,
      duplicate.disclosureLevelCommitment,
      duplicate.policyId,
      duplicate.trustLevel,
      duplicate.evidenceHash,
      duplicateProof.verifierAuthorizationId,
      duplicateProof.verifierKeyIdCommitment,
      duplicateProof.evidenceSignature,
    )).toThrow(/live authorization/i);
    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:passport:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_VERIFIER_ACTION_KIND,
          computeUpdateVerifierAuthorizationPayloadHash(
            verifierAuthorization.authorizationId,
            simulator.getVerifierAuthorization(verifierAuthorization.authorizationId)
              .lifecycleEventHash,
            labelToBytes32("evidence:passport:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        verifierAuthorization.authorizationId,
        labelToBytes32("evidence:passport:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active recognition by id and scope", () => {
    const registry = createInitializedRegistryFixture(43);
    const {
      simulator,
    } = registry;
    const recognition = createRecognitionFixture("gaia-x");
    const eventHash = activateRecognitionFixture(registry, recognition);
    const state = simulator.getLedger();
    const recordById = simulator.getRecognition(recognition.recognitionId);
    const recordByScope = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );

    expect(state.recognitionCount).toEqual(1n);
    expect(state.activeRecognitionCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(recordById.recognitionId)).toEqual(
      Buffer.from(recognition.recognitionId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.recognitionId)).toEqual(
      Buffer.from(recognition.recognitionId),
    );
    expect(() =>
      simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).not.toThrow();
  });

  it("binds recognition proposal evidence to its scope and an active verifier key", () => {
    const registry = createInitializedRegistryFixture(44);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const recognition = createRecognitionFixture("recognition-proof");
    const proof = recognitionProposalProof(registry, recognition, recognition.evidenceHash);
    const sign = (kind: Uint8Array, payloadHash: Uint8Array) =>
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        simulator.getLedger().governancePolicyCommitment,
        kind, payloadHash, simulator.getLedger().governanceActionCount,
      );
    const propose = (
      payloadHash: Uint8Array,
      evidenceSignature: typeof proof.evidenceSignature,
      recognizedRegistryId = recognition.recognizedRegistryId,
    ) => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      sign(PROPOSE_RECOGNITION_ACTION_KIND, payloadHash),
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
      proof.verifierAuthorizationId,
      proof.verifierKeyIdCommitment,
      evidenceSignature,
    );

    expect(() => propose(proof.payloadHash, {
      ...proof.evidenceSignature,
      response: 0n,
    })).toThrow(/invalid jubjub schnorr signature/i);
    const substitutedRegistryId = labelToBytes32("registry:substituted");
    const substitutedBase = computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      substitutedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );
    const substitutedPayload = computeRecognitionEvidenceBoundProposalPayloadHash(
      substitutedBase,
      proof.verifierAuthorizationId,
      proof.verifierKeyIdCommitment,
      simulator.getLedger().governancePolicyCommitment,
      simulator.getLedger().governancePolicyVersion,
    );
    expect(() => propose(
      substitutedPayload, proof.evidenceSignature, substitutedRegistryId,
    )).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().recognitionCount).toEqual(0n);

    const eventHash = propose(proof.payloadHash, proof.evidenceSignature);
    const stored = simulator.getRecognitionProposalEvidence(recognition.recognitionId);
    expect(Buffer.from(stored.evidenceVerifierAuthorizationId)).toEqual(
      Buffer.from(proof.verifierAuthorizationId),
    );
    expect(Buffer.from(stored.evidenceCommitment)).toEqual(Buffer.from(recognition.evidenceHash));
    expect(Buffer.from(stored.proposalGovernanceEventHash)).toEqual(Buffer.from(eventHash));
    expect(stored.verifierSignatureResponse).toEqual(proof.evidenceSignature.response);

    const suspensionReason = labelToBytes32("reason:recognition-verifier-suspend");
    simulator.suspendEvidenceVerifierKey(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      sign(SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
        computeUpdateEvidenceVerifierKeyPayloadHash(
          proof.verifierAuthorizationId,
          simulator.getEvidenceVerifierKey(proof.verifierAuthorizationId).lifecycleEventHash,
          suspensionReason,
        )),
      proof.verifierAuthorizationId,
      suspensionReason,
    );
    expect(() => simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      sign(AUTHORIZE_RECOGNITION_ACTION_KIND,
        computeUpdateRecognitionPayloadHash(
          recognition.recognitionId,
          eventHash,
          recognition.evidenceHash,
        )),
      recognition.recognitionId,
      recognition.evidenceHash,
    )).toThrow(/evidence verifier key is not active/i);
    expect(simulator.getRecognition(recognition.recognitionId).status).toEqual(
      AuthorizationStatus.proposed,
    );
  });

  it("moves a recognition through proposed, authorized, and active states", () => {
    const registry = createInitializedRegistryFixture(45);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("gaia-x-application");
    const proposedEvidenceHash = labelToBytes32("evidence:gaia-x-application:propose");
    const replacementEvidenceHash = labelToBytes32("evidence:gaia-x-application:replacement");
    const proof = recognitionProposalProof(registry, recognition, proposedEvidenceHash);

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_RECOGNITION_ACTION_KIND,
      proof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      proposedEvidenceHash,
      proof.verifierAuthorizationId,
      proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    );

    const proposedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const replacementAuthorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementAuthorizeSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )).toThrow(/evidence must match the proposed application/i);
    expect(simulator.getRecognition(recognition.recognitionId).status).toEqual(
      AuthorizationStatus.proposed,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    );

    const authorizedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const replacementActivateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementActivateSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )).toThrow(/activation evidence must match the proposed application/i);
    expect(simulator.getRecognition(recognition.recognitionId).status).toEqual(
      AuthorizationStatus.authorized,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    );

    const activeRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(1n);
  });

  it("suspends, revokes, and archives recognition records while preserving append-only scope state", () => {
    const registry = createInitializedRegistryFixture(47);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("eidas");
    activateRecognitionFixture(registry, recognition);

    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const suspendEvidenceHash = labelToBytes32("evidence:eidas:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      recognition.recognitionId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);
    expect(() =>
      simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:eidas:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      recognition.recognitionId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:eidas:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);
  });

  it("rejects duplicate recognition scopes, invalid transitions, tampered signatures, and missing recognition queries", () => {
    const registry = createInitializedRegistryFixture(53);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("gaia-net");
    const proof = recognitionProposalProof(registry, recognition, recognition.evidenceHash);

    expect(() =>
      simulator.getRecognition(labelToBytes32("recognition:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentRecognition(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).toThrow(/scope is not registered/i);

    const proposePayloadHash = proof.payloadHash;
    const tamperedProposeSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        proposePayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };
    expect(() => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      tamperedProposeSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
      proof.verifierAuthorizationId,
      proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateRecognitionFixture(registry, recognition);
    const duplicate = {
      ...recognition,
      recognitionId: labelToBytes32("recognition:gaia-net:duplicate"),
      evidenceHash: labelToBytes32("evidence:gaia-net:duplicate"),
    };
    const duplicateProof = recognitionProposalProof(registry, duplicate, duplicate.evidenceHash);
    expect(() => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        duplicateProof.payloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      duplicate.recognitionId,
      duplicate.recognizedAuthorityDidCommitment,
      duplicate.recognizedRegistryId,
      duplicate.scopeResourceType,
      duplicate.scopeResourceId,
      duplicate.policyId,
      duplicate.trustLevel,
      duplicate.evidenceHash,
      duplicateProof.verifierAuthorizationId,
      duplicateProof.verifierKeyIdCommitment,
      duplicateProof.evidenceSignature,
    )).toThrow(/live recognition/i);
    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const archiveEvidenceHash = labelToBytes32("evidence:gaia-net:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeRecognition(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_RECOGNITION_ACTION_KIND,
          computeUpdateRecognitionPayloadHash(
            recognition.recognitionId,
            simulator.getRecognition(recognition.recognitionId)
              .lifecycleEventHash,
            labelToBytes32("evidence:gaia-net:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        recognition.recognitionId,
        labelToBytes32("evidence:gaia-net:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("keeps two full request resources for one auditor and partial request tuple distinct", () => {
    const registry = createInitializedRegistryFixture(56);
    const first = createAuditorAuthorizationFixture("same-profile");
    const second = {
      ...first,
      authorizationId: labelToBytes32("auditor-auth:same-profile:other-purpose"),
      requestResourceId: labelToBytes32("audit-request-resource:alt"),
      evidenceHash: labelToBytes32("evidence:audit-same-profile:other-purpose"),
    };
    expect(Buffer.from(second.requestResourceId)).not.toEqual(Buffer.from(first.requestResourceId));
    activateAuditorAuthorizationFixture(registry, first);
    activateAuditorAuthorizationFixture(registry, second);
    expect(registry.simulator.getLedger().activeAuditorAuthorizationCount).toBe(2n);
    for (const authorization of [first, second]) {
      const current = registry.simulator.getCurrentAuditorAuthorization(
        authorization.subjectDidCommitment,
        authorization.requestResourceId,
        authorization.allowedAttributeSetCommitment,
        authorization.allowedPredicateSetCommitment,
        authorization.disclosureLevelCommitment,
      );
      expect(Buffer.from(current.authorizationId)).toEqual(Buffer.from(authorization.authorizationId));
    }
  });

  it("requires a registered evidence-verifier signature for auditor proposals", () => {
    const registry = createInitializedRegistryFixture(60);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const auditor = createAuditorAuthorizationFixture("signed-mandate");
    const proof = auditorProposalProof(registry, auditor);
    const sign = () => signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash, simulator.getLedger().governanceActionCount,
    );
    const propose = (keyId: Uint8Array, evidenceSignature: typeof proof.evidenceSignature) =>
      simulator.proposeAuditorAuthorization(
        bootstrapMaintainer.keyId, bootstrapPublicKey, sign(),
        auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
        auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
        auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel,
        auditor.evidenceHash, proof.verifierAuthorizationId, keyId, evidenceSignature,
      );
    expect(() => simulator.getAuditorProposalEvidence(auditor.authorizationId)).toThrow(/not registered/i);
    expect(() => propose(labelToBytes32("wrong-evidence-verifier-key"), proof.evidenceSignature))
      .toThrow(/key id does not match/i);
    expect(() => propose(proof.verifierKeyIdCommitment,
      signVerifierProposalEvidenceFromSeed(
        new Uint8Array(32).fill(97), registryId, FIXTURE_NETWORK_ID_COMMITMENT,
        encodeContractAddress(simulator.contractAddress), proof.verifierKeyIdCommitment, proof.payloadHash,
      ))).toThrow(/invalid jubjub schnorr signature/i);
    expect(simulator.getLedger().auditorAuthorizationCount).toBe(0n);
    const eventHash = propose(proof.verifierKeyIdCommitment, proof.evidenceSignature);
    const evidence = simulator.getAuditorProposalEvidence(auditor.authorizationId);
    expect(evidence.evidenceCommitment).toEqual(auditor.evidenceHash);
    expect(evidence.evidenceVerifierKeyIdCommitment).toEqual(proof.verifierKeyIdCommitment);
    expect(evidence.proposalGovernanceEventHash).toEqual(eventHash);
    expect(() => propose(proof.verifierKeyIdCommitment, proof.evidenceSignature))
      .toThrow(/already exists/i);
  });

  it("rejects auditor approval after its proposal evidence policy is superseded", () => {
    const registry = createInitializedRegistryFixture(61);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const auditor = createAuditorAuthorizationFixture("stale-mandate");
    const proof = auditorProposalProof(registry, auditor);
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash, simulator.getLedger().governanceActionCount,
    );
    simulator.proposeAuditorAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, proposalSignature,
      auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
      auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
      auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel,
      auditor.evidenceHash, proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    );
    const proposalEvent = simulator.getAuditorProposalEvidence(auditor.authorizationId).proposalGovernanceEventHash;
    const oldPolicy = simulator.getLedger().governancePolicyCommitment;
    const newPolicy = labelToBytes32("policy:auditor:evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      oldPolicy, newPolicy, 2n, 1n, 1n, 1n,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, oldPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyHash,
        simulator.getLedger().governanceActionCount,
      ),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    const record = simulator.getAuditorAuthorization(auditor.authorizationId);
    const approvalHash = computeUpdateAuditorAuthorizationPayloadHash(
      auditor.authorizationId, record.lifecycleEventHash, auditor.evidenceHash,
    );
    expect(() => simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, newPolicy, AUTHORIZE_AUDITOR_ACTION_KIND,
        approvalHash, simulator.getLedger().governanceActionCount,
      ),
      auditor.authorizationId, auditor.evidenceHash,
    )).toThrow(/proposal evidence policy is not current/i);
    expect(simulator.getAuditorAuthorization(auditor.authorizationId).status).toBe(AuthorizationStatus.proposed);
    expect(simulator.getAuditorProposalEvidence(auditor.authorizationId).proposalGovernanceEventHash)
      .toEqual(proposalEvent);
  });

  it("creates and governs auditor authorizations across proposal, activation, and archival paths", () => {
    const registry = createInitializedRegistryFixture(57);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const auditorAuthorization = createAuditorAuthorizationFixture("iso-27001");
    const proposalEvidenceHash = labelToBytes32("evidence:iso-27001:propose");
    const proposalProof = auditorProposalProof(registry,
      { ...auditorAuthorization, evidenceHash: proposalEvidenceHash });

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND,
      proposalProof.payloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      auditorAuthorization.authorizationId,
      auditorAuthorization.subjectDidCommitment,
      auditorAuthorization.requestResourceId,
      auditorAuthorization.allowedAttributeSetCommitment,
      auditorAuthorization.allowedPredicateSetCommitment,
      auditorAuthorization.disclosureLevelCommitment,
      auditorAuthorization.policyId,
      auditorAuthorization.trustLevel,
      proposalEvidenceHash,
      proposalProof.verifierAuthorizationId,
      proposalProof.verifierKeyIdCommitment,
      proposalProof.evidenceSignature,
    );

    const proposedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);

    const substitutedAuthorizationEvidence = labelToBytes32("evidence:iso-27001:authorize:substituted");
    expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        substitutedAuthorizationEvidence,
      ),
      (signature) => simulator.authorizeAuditorAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        auditorAuthorization.authorizationId,
        substitutedAuthorizationEvidence,
      ),
      /auditor authorization evidence must match the proposed application/i,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposedRecord.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      auditorAuthorization.authorizationId,
      proposedRecord.evidenceHash,
    );

    const authorizedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);

    const substitutedActivationEvidence = labelToBytes32("evidence:iso-27001:activate:substituted");
    expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      (signature) => simulator.activateAuditorAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        auditorAuthorization.authorizationId,
        substitutedActivationEvidence,
      ),
      /auditor activation evidence must match the proposed application/i,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        authorizedRecord.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      auditorAuthorization.authorizationId,
      authorizedRecord.evidenceHash,
    );

    const activeRecord = simulator.getCurrentAuditorAuthorization(
      auditorAuthorization.subjectDidCommitment,
      auditorAuthorization.requestResourceId,
      auditorAuthorization.allowedAttributeSetCommitment,
      auditorAuthorization.allowedPredicateSetCommitment,
      auditorAuthorization.disclosureLevelCommitment,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeAuditorAuthorizationCount).toEqual(1n);
    expect(() =>
      simulator.assertAuditorAuthorized(
        auditorAuthorization.subjectDidCommitment,
        auditorAuthorization.requestResourceId,
        auditorAuthorization.allowedAttributeSetCommitment,
        auditorAuthorization.allowedPredicateSetCommitment,
        auditorAuthorization.disclosureLevelCommitment,
      ),
    ).not.toThrow();

    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        activeRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:revoke"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:revoke"),
    );
    expect(simulator.getLedger().activeAuditorAuthorizationCount).toEqual(0n);

    const revokedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:archive"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:archive"),
    );
    expect(
      simulator.getAuditorAuthorization(auditorAuthorization.authorizationId).status,
    ).toEqual(AuthorizationStatus.archived);
  });

  it("publishes and queries an epoch commitment by id and latest pointer", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(59);
    const epoch = createEpochCommitmentFixture(
      "seq-1",
      simulator.getLedger().governancePolicyCommitment,
    );
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
      actionSequence,
    );

    const eventHash = simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );
    const state = simulator.getLedger();
    const recordById = simulator.getEpochCommitment(epoch.epochId);
    const recordByLatest = simulator.getCurrentEpochCommitment();

    expect(state.epochCommitmentCount).toEqual(1n);
    expect(Buffer.from(state.latestEpochCommitmentId)).toEqual(
      Buffer.from(epoch.epochId),
    );
    expect(Buffer.from(recordById.epochId)).toEqual(Buffer.from(epoch.epochId));
    expect(Buffer.from(recordById.stateRoot)).toEqual(Buffer.from(epoch.stateRoot));
    expect(Buffer.from(recordById.eventRoot)).toEqual(Buffer.from(epoch.eventRoot));
    expect(Buffer.from(recordById.policyRoot)).toEqual(
      Buffer.from(epoch.policyRoot),
    );
    expect(Buffer.from(recordById.publicationPolicyCommitment)).toEqual(
      Buffer.from(state.governancePolicyCommitment),
    );
    expect(recordById.validFromSequence).toEqual(epoch.validFromSequence);
    expect(recordById.validUntilSequence).toEqual(epoch.validUntilSequence);
    expect(Buffer.from(recordById.publicationEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByLatest.epochId)).toEqual(Buffer.from(epoch.epochId));
    expect(recordByLatest.signatureResponse).toEqual(signature.response);
  });

  it("rejects missing epoch queries, invalid epoch windows, tampered signatures, and duplicate epoch ids", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(61);
    const epoch = createEpochCommitmentFixture(
      "seq-2",
      simulator.getLedger().governancePolicyCommitment,
    );

    expect(() => simulator.getCurrentEpochCommitment()).toThrow(
      /no epoch commitment/i,
    );
    expect(() =>
      simulator.getEpochCommitment(labelToBytes32("epoch:missing")),
    ).toThrow(/not registered/i);

    expect(() =>
      pureCircuits.createEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        10n,
        9n,
      ),
    ).toThrow(/later than valid from/i);

    const createPayloadHash = computeCreateEpochCommitmentPayloadHash(
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );
    const tamperedSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        CREATE_EPOCH_ACTION_KIND,
        createPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const uncommittedPolicyRoot = labelToBytes32("policy-root:uncommitted");
    const uncommittedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        uncommittedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/committed governance policy/i);

    const futureFrom = simulator.getLedger().governanceActionCount + 1n;
    const futureSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        futureSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      ),
    ).toThrow(/cannot start after its publication action/i);

    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      createPayloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );

    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          CREATE_EPOCH_ACTION_KIND,
          computeCreateEpochCommitmentPayloadHash(
            epoch.epochId,
            labelToBytes32("state-root:duplicate"),
            epoch.eventRoot,
            epoch.policyRoot,
            epoch.validFromSequence,
            epoch.validUntilSequence,
          ),
          simulator.getLedger().governanceActionCount,
        ),
        epoch.epochId,
        labelToBytes32("state-root:duplicate"),
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/already exists/i);

    const revisionSequence = simulator.getLedger().governanceActionCount;
    const revisedPolicyRoot = labelToBytes32("policy:kanon:v2");
    const revisionSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        epoch.policyRoot,
        revisedPolicyRoot,
        2n,
        1n,
        1n,
        1n,
      ),
      revisionSequence,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revisionSignature,
      revisedPolicyRoot,
      2n,
      1n,
      1n,
      1n,
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(epoch.policyRoot),
    );
    const revisionEventHash = simulator.getLedger().lastGovernanceEventHash;
    expect(Buffer.from(revisionEventHash)).toEqual(Buffer.from(pureCircuits.governanceEventHash(
      registryId,
      FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress),
      epoch.policyRoot,
      simulator.getLedger().lastAuthorizedSignerSetHash,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        epoch.policyRoot,
        revisedPolicyRoot,
        2n,
        1n,
        1n,
        1n,
      ),
      revisionSequence,
    )));

    const historicalEpochId = labelToBytes32("epoch:historical-old-policy");
    const historicalFrom = epoch.validFromSequence;
    const historicalUntil = epoch.validUntilSequence;
    const historicalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        historicalEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        historicalFrom,
        historicalUntil,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      historicalSignature,
      historicalEpochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      historicalFrom,
      historicalUntil,
    );
    const historicalRecord = simulator.getEpochCommitment(historicalEpochId);
    expect(Buffer.from(historicalRecord.policyRoot)).toEqual(Buffer.from(epoch.policyRoot));
    expect(Buffer.from(historicalRecord.publicationPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect(simulator.getLedger().governanceEventHashes.member(revisionEventHash)).toBe(true);

    const lateSequence = simulator.getLedger().governanceActionCount;
    const lateEpochId = labelToBytes32("epoch:late-old-policy");
    const lateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        lateEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        lateSequence,
        lateSequence + 60n,
      ),
      lateSequence,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        lateSignature,
        lateEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        lateSequence,
        lateSequence + 60n,
      ),
    ).toThrow(/superseded at this sequence/i);
  });
});
