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

it("encodes Compact action kinds exactly and rejects overlong values", async () => {
  expect(encodeCompactActionKind("tr:epoch:publish")).toEqual(labelToBytes32("tr:epoch:publish"));
  expect(() => encodeCompactActionKind(`tr:${"x".repeat(30)}`)).toThrow(/exceeds Compact Bytes<32>/);
});

it("uses the default meta-governance quorum for threshold policy revisions", async () => {
  const updateKind = encodeCompactActionKind("tr:policy:thresholds:update");
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 1n, 2n, 3n)).toBe(1n);
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 3n, 2n, 1n)).toBe(3n);
  expect(pureCircuits.actionScopedMaintainerThreshold(updateKind, 1n, 3n, 2n)).toBe(1n);
  expect(pureCircuits.actionScopedMaintainerThreshold(
    encodeCompactActionKind("tr:issuer:authorize"), 1n, 2n, 3n,
  )).toBe(1n);
});

it("requires both current policy and emergency quorums for atomic recovery", async () => {
  expect(pureCircuits.actionScopedMaintainerThreshold(
    RECOVER_MAINTAINER_ACTION_KIND, 2n, 3n, 2n,
  )).toBe(3n);
  expect(pureCircuits.actionScopedMaintainerThreshold(
    RECOVER_MAINTAINER_ACTION_KIND, 3n, 2n, 2n,
  )).toBe(3n);
});

it("rejects malformed fixture labels before UTF-8 replacement can alias them", async () => {
  expect(() => labelToBytes32(`${"x".repeat(31)}\ud800`)).toThrow(/valid UTF-16/);
  expect(() => labelToBytes32(`${"x".repeat(31)}\udc00`)).toThrow(/valid UTF-16/);
  expect(labelToBytes32("valid-\ud83d\ude00")).toHaveLength(32);
});

it("hashes only strictly sorted, distinct maintainer key ids with zero padding", async () => {
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

it("pins every governed action kind to a Compact literal", async () => {
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
  const registryId = labelToBytes32("registry:midnight");
  const registryDidCommitment = labelToBytes32("did:midnight:registry");
  const governancePolicyCommitment = labelToBytes32("policy:midnight:v1");
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
  policyId: labelToBytes32("policy:midnight:v1"),
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

const registerIssuerEvidenceVerifier = async (
  registry: RegistryFixture,
  coMaintainer?: ReturnType<typeof createMaintainerMembershipFixture>,
) => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const existing = evidenceVerifiers.get(simulator);
  const ledger = await simulator.getLedger();
  const policyCommitment = ledger.governancePolicyCommitment;
  const policyVersion = ledger.governancePolicyVersion;
  if (existing && (await simulator.getEvidenceVerifierKey(existing.authorizationId)).policyVersion === policyVersion) {
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
  const sequence = ledger.governanceActionCount;
  await simulator.registerEvidenceVerifierKey(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, policyCommitment,
      REGISTER_EVIDENCE_VERIFIER_ACTION_KIND, payloadHash, sequence,
    ),
    verifier.authorizationId, verifier.didCommitment, verifier.keyId, verifier.publicKey,
    labelToBytes32("jubjub-schnorr"), policyCommitment, policyVersion,
    coMaintainer ? [await createMaintainerCoAuthorizer(
      coMaintainer, simulator, registryId, REGISTER_EVIDENCE_VERIFIER_ACTION_KIND,
      payloadHash, sequence,
    )] : [],
  );
  evidenceVerifiers.set(simulator, verifier);
  return verifier;
};

const issuerProposalProof = async (
  registry: RegistryFixture,
  issuer: IssuerFixture,
  verifier: Awaited<ReturnType<typeof registerIssuerEvidenceVerifier>>,
) => {
  const { simulator, registryId } = registry;
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
    issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
    issuer.trustLevel, issuer.evidenceHash,
  );
  const ledger = await simulator.getLedger();
  const payloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    ledger.governancePolicyCommitment,
    ledger.governancePolicyVersion,
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

const recognitionProposalProof = async (
  registry: RegistryFixture,
  recognition: ReturnType<typeof createRecognitionFixture>,
  evidenceHash: Uint8Array,
) => {
  const verifier = await registerIssuerEvidenceVerifier(registry);
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
  const ledger = await simulator.getLedger();
  const payloadHash = computeRecognitionEvidenceBoundProposalPayloadHash(
    baseHash,
    verifier.authorizationId,
    verifier.keyId,
    ledger.governancePolicyCommitment,
    ledger.governancePolicyVersion,
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

const verifierProposalProof = async (
  registry: RegistryFixture,
  verifierAuthorization: ReturnType<typeof createVerifierAuthorizationFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = await registerIssuerEvidenceVerifier(registry);
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
  const ledger = await simulator.getLedger();
  const payloadHash = computeVerifierEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    ledger.governancePolicyCommitment,
    ledger.governancePolicyVersion,
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

const activateIssuerAuthorizationFixture = async (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createIssuerAuthorizationFixture>,
): Promise<Uint8Array> => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = await issuerProposalProof(
    registry, authorization, await registerIssuerEvidenceVerifier(registry),
  );
  const sign = async (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );

  await simulator.proposeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
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
  await simulator.authorizeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(AUTHORIZE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getIssuerAuthorization(authorization.authorizationId)).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return (await simulator.activateIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(ACTIVATE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getIssuerAuthorization(authorization.authorizationId)).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  ));
};

const createVerifierAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`verifier-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:verifier:${label}`),
  requestResourceId: labelToBytes32(`request-resource:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`pred-set:${label}:adult`),
  disclosureLevelCommitment: labelToBytes32(`disclosure:${label}:selective`),
  policyId: labelToBytes32("policy:midnight:v1"),
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
  policyId: labelToBytes32("policy:midnight:v1"),
  trustLevel: labelToBytes32("peer-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const activateVerifierAuthorizationFixture = async (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createVerifierAuthorizationFixture>,
): Promise<Uint8Array> => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = await verifierProposalProof(registry, authorization);
  const sign = async (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
  await simulator.proposeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(PROPOSE_VERIFIER_ACTION_KIND, proof.payloadHash),
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
  await simulator.authorizeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(AUTHORIZE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getVerifierAuthorization(authorization.authorizationId)).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return (await simulator.activateVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(ACTIVATE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getVerifierAuthorization(authorization.authorizationId)).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  ));
};

const activateRecognitionFixture = async (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  recognition: ReturnType<typeof createRecognitionFixture>,
): Promise<Uint8Array> => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = await recognitionProposalProof(registry, recognition, recognition.evidenceHash);
  const sign = async (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
  await simulator.proposeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(PROPOSE_RECOGNITION_ACTION_KIND, proof.payloadHash),
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
  await simulator.authorizeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(AUTHORIZE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      (await simulator.getRecognition(recognition.recognitionId)).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  );
  return (await simulator.activateRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(ACTIVATE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      (await simulator.getRecognition(recognition.recognitionId)).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  ));
};

const createAuditorAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`auditor-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:auditor:${label}`),
  requestResourceId: labelToBytes32(`audit-request-resource:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`audit-attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`audit-pred-set:${label}:compliance`),
  disclosureLevelCommitment: labelToBytes32(`audit-disclosure:${label}:restricted`),
  policyId: labelToBytes32("policy:midnight:v1"),
  trustLevel: labelToBytes32("audit-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const auditorProposalProof = async (
  registry: RegistryFixture,
  auditor: ReturnType<typeof createAuditorAuthorizationFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = await registerIssuerEvidenceVerifier(registry);
  const baseHash = computeCreateAuditorAuthorizationPayloadHash(
    auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
    auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
    auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel, auditor.evidenceHash,
  );
  const ledger = await simulator.getLedger();
  const payloadHash = computeAuditorEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    ledger.governancePolicyCommitment,
    ledger.governancePolicyVersion,
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

const activateAuditorAuthorizationFixture = async (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createAuditorAuthorizationFixture>,
): Promise<void> => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const proof = await auditorProposalProof(registry, authorization);
  const sign = async (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
  await simulator.proposeAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash),
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
  await simulator.authorizeAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(AUTHORIZE_AUDITOR_ACTION_KIND, computeUpdateAuditorAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getAuditorAuthorization(authorization.authorizationId)).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  await simulator.activateAuditorAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    await sign(ACTIVATE_AUDITOR_ACTION_KIND, computeUpdateAuditorAuthorizationPayloadHash(
      authorization.authorizationId,
      (await simulator.getAuditorAuthorization(authorization.authorizationId)).lifecycleEventHash,
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
    policyId: labelToBytes32("policy:midnight:v1"),
    trustLevel: labelToBytes32("governance-approved"),
    evidenceHash: labelToBytes32(`evidence:${label}:propose`),
    seed: candidate.seed,
  };
};

const maintainerProposalProof = async (
  registry: RegistryFixture,
  candidate: ReturnType<typeof createMaintainerMembershipFixture>,
) => {
  const { simulator, registryId } = registry;
  const verifier = await registerIssuerEvidenceVerifier(registry);
  const baseHash = computeCreateMaintainerMembershipPayloadHash(
    candidate.maintainerId, candidate.maintainerDidCommitment, candidate.keyId,
    candidate.publicKey, candidate.policyId, candidate.trustLevel, candidate.evidenceHash,
  );
  const ledger = await simulator.getLedger();
  const payloadHash = computeMaintainerEvidenceBoundProposalPayloadHash(
    baseHash, verifier.authorizationId, verifier.keyId,
    ledger.governancePolicyCommitment,
    ledger.governancePolicyVersion,
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

const createMaintainerCoAuthorizer = async (
  maintainer: ReturnType<typeof createMaintainerMembershipFixture>,
  simulator: TrustRegistrySimulator,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): Promise<MaintainerCoAuthorizer> => ({
  keyId: maintainer.keyId,
  publicKey: maintainer.publicKey,
  signature: signFixtureDeploymentBoundActionFromSeed(simulator,
    maintainer.seed,
    registryId,
    (await simulator.getLedger()).governancePolicyCommitment,
    actionKind,
    actionPayloadHash,
    actionSequence,
  ),
});

const activateAdditionalMaintainer = async (
  registry: RegistryFixture,
  candidate: ReturnType<typeof createMaintainerMembershipFixture>,
): Promise<void> => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = async (kind: Uint8Array, payloadHash: Uint8Array) =>
    signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      kind, payloadHash, (await simulator.getLedger()).governanceActionCount,
    );
  const proof = await maintainerProposalProof(registry, candidate);
  await simulator.proposeMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash),
    candidate.maintainerId, candidate.maintainerDidCommitment,
    candidate.keyId, candidate.publicKey, candidate.policyId, candidate.trustLevel,
    candidate.evidenceHash, proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
    proof.evidenceSignature,
  );
  const authorizeRecord = await simulator.getMaintainerMembership(candidate.maintainerId);
  await simulator.authorizeMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    await sign(AUTHORIZE_MAINTAINER_ACTION_KIND, computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, authorizeRecord.lifecycleEventHash, candidate.evidenceHash,
    )),
    candidate.maintainerId, candidate.evidenceHash,
  );
  const activateRecord = await simulator.getMaintainerMembership(candidate.maintainerId);
  await simulator.activateMaintainerMembership(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    await sign(ACTIVATE_MAINTAINER_ACTION_KIND, computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, activateRecord.lifecycleEventHash, candidate.evidenceHash,
    )),
    candidate.maintainerId, candidate.evidenceHash,
  );
};

const expectSignedEvidenceMismatch = async (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  actionKind: Uint8Array,
  payloadHash: Uint8Array,
  invoke: (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) => Promise<unknown>,
  diagnostic: RegExp,
): Promise<void> => {
  const signature = signFixtureDeploymentBoundActionFromSeed(registry.simulator,
    registry.bootstrapMaintainer.seed,
    registry.registryId,
    (await registry.simulator.getLedger()).governancePolicyCommitment,
    actionKind,
    payloadHash,
    (await registry.simulator.getLedger()).governanceActionCount,
  );
  await expect(invoke(signature)).rejects.toThrow(diagnostic);
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
  it("keeps distinct long and multibyte fixture labels distinct", async () => {
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

  it("binds action payload hashes to deployment and policy commitments", async () => {
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

  it("signs a deployment-bound action digest under one explicit policy snapshot", async () => {
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

  it("accepts valid threshold rules and rejects invalid ones", async () => {
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

  it("records a network-bound initialization event before a contract address exists", async () => {
    const registryId = labelToBytes32("registry:midnight");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:midnight:v1");
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

    const state = await simulator.getLedger();
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
    expect((await sameNetwork.getLedger()).lastGovernanceEventHash).toEqual(state.lastGovernanceEventHash);
    expect((await otherNetwork.getLedger()).lastGovernanceEventHash).not.toEqual(state.lastGovernanceEventHash);
    expect(maintainer.status).toEqual(MaintainerStatus.active);
    expect(Buffer.from(maintainer.keyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects invalid deployment bootstrap inputs and exposes no first-call initializer", async () => {
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 9);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const bootstrap = {
      registryId: labelToBytes32("registry:midnight"),
      networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
      registryDidCommitment: labelToBytes32("did:midnight:registry"),
      governancePolicyCommitment: labelToBytes32("policy:midnight:v1"),
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    };

    await expect(
      new TrustRegistrySimulator({ ...bootstrap, registryId: new Uint8Array(32) }).getLedger(),
    ).rejects.toThrow(/Registry id must be set/);

    await expect(
      new TrustRegistrySimulator({ ...bootstrap, networkIdCommitment: new Uint8Array(32) }).getLedger(),
    ).rejects.toThrow(/Deployment network id commitment must be set/);

    await expect(
      new TrustRegistrySimulator({ ...bootstrap, governancePolicyCommitment: new Uint8Array(32) }).getLedger(),
    ).rejects.toThrow(/Governance policy commitment must be set/);

    await expect(
      new TrustRegistrySimulator({ ...bootstrap, maintainerThreshold: 0n }).getLedger(),
    ).rejects.toThrow(/threshold must be at least 1/i);

    await expect(
      new TrustRegistrySimulator({ ...bootstrap, maintainerThreshold: 2n }).getLedger(),
    ).rejects.toThrow(/may not exceed active maintainer count/i);

    await expect(
      new TrustRegistrySimulator({
        ...bootstrap,
        maintainerPublicKey: { x: 0n, y: 1n },
      }).getLedger(),
    ).rejects.toThrow(/signer point must not be identity/i);

    const lowOrderKey = {
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    };
    await expect(new TrustRegistrySimulator({
      ...bootstrap,
      maintainerPublicKey: lowOrderKey,
    }).getLedger()).rejects.toThrow();

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
    expect((await simulator.getLedger()).initialized).toBe(true);
    expect((await simulator.getLedger()).deploymentNetworkIdCommitment).toEqual(bootstrap.networkIdCommitment);
    expect(simulator.contract.impureCircuits).not.toHaveProperty("initializeRegistry");
  });

  it("does not let an unauthorized first caller replace constructor bootstrap state", async () => {
    const registry = createInitializedRegistryFixture(10);
    const { simulator, registryId, bootstrapMaintainer } = registry;
    const original = await simulator.getLedger();
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

    await expect(simulator.authorizeMaintainerAuditEvent(
      attacker.keyId,
      deriveJubjubPublicKeyFromSeed(attacker.seed),
      attackerSignature,
      payloadHash,
    )).rejects.toThrow(/not registered/i);
    const after = await simulator.getLedger();
    expect(after.governanceActionCount).toBe(1n);
    expect(after.registryId).toEqual(registryId);
    expect(after.lastAuthorizedMaintainerKeyId).toEqual(bootstrapMaintainer.keyId);
    expect(simulator.contract.impureCircuits).not.toHaveProperty("initializeRegistry");
  });

  it("invalidates an unsubmitted proposal signature after another governed action advances the sequence", async () => {
    const registry = createInitializedRegistryFixture(71);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuer = createIssuerAuthorizationFixture("recovery-sequence");
    const verifier = await registerIssuerEvidenceVerifier(registry);
    const proposal = await issuerProposalProof(registry, issuer, verifier);
    const reservedSequence = (await simulator.getLedger()).governanceActionCount;
    const reservedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proposal.payloadHash, reservedSequence,
    );

    const auditPayload = labelToBytes32("recovery:advance-sequence");
    const auditSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      GENERIC_AUDIT_ACTION_KIND, auditPayload, reservedSequence,
    );
    await simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId, bootstrapPublicKey, auditSignature, auditPayload,
    );
    expect((await simulator.getLedger()).governanceActionCount).toBe(reservedSequence + 1n);
    expect((await simulator.getLedger()).issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(false);

    const propose = async (signature: typeof reservedSignature) => (await simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
      issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
      issuer.trustLevel, issuer.evidenceHash, proposal.verifierAuthorizationId,
      proposal.verifierKeyIdCommitment, proposal.evidenceSignature,
    ));
    await expect(propose(reservedSignature)).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(reservedSequence + 1n);
    expect((await simulator.getLedger()).issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(false);

    const freshSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proposal.payloadHash, reservedSequence + 1n,
    );
    await propose(freshSignature);
    expect((await simulator.getLedger()).issuerProposalEvidenceRecords.member(issuer.authorizationId)).toBe(true);
  });

  it("governs maintainer membership through proposal, approval, activation, suspension, revocation, and archival", async () => {
    const registry = createInitializedRegistryFixture(11);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const candidate = createMaintainerMembershipFixture("governed", 12);
    const proposalProof = await maintainerProposalProof(registry, candidate);

    const proposeActionSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeActionSequence,
    );

    (await simulator.proposeMaintainerMembership(
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
    ));

    const proposedMembership = (await simulator.getMaintainerMembership(
      candidate.maintainerId,
    ));
    expect(proposedMembership.status).toEqual(AuthorizationStatus.proposed);

    const substitutedEvidence = labelToBytes32("evidence:governed:authorize:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        proposedMembership.lifecycleEventHash,
        substitutedEvidence,
      ),
      async (signature) => (await simulator.authorizeMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        candidate.maintainerId,
        substitutedEvidence,
      )),
      /maintainer authorization evidence must match the proposed application/i,
    );

    const authorizeEvidenceHash = candidate.evidenceHash;
    const authorizeActionSequence = (await simulator.getLedger()).governanceActionCount;
    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        proposedMembership.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      authorizeActionSequence,
    );

    (await simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      candidate.maintainerId,
      authorizeEvidenceHash,
    ));

    const authorizedMembership = (await simulator.getMaintainerMembership(
      candidate.maintainerId,
    ));
    expect(authorizedMembership.status).toEqual(AuthorizationStatus.authorized);

    const substitutedActivationEvidence = labelToBytes32("evidence:governed:activate:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        authorizedMembership.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      async (signature) => (await simulator.activateMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        candidate.maintainerId,
        substitutedActivationEvidence,
      )),
      /maintainer activation evidence must match the proposed application/i,
    );

    const activateEvidenceHash = candidate.evidenceHash;
    const activateActionSequence = (await simulator.getLedger()).governanceActionCount;
    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        authorizedMembership.lifecycleEventHash,
        activateEvidenceHash,
      ),
      activateActionSequence,
    );

    (await simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      candidate.maintainerId,
      activateEvidenceHash,
    ));

    const activeMembership = (await simulator.getCurrentMaintainerMembership(
      candidate.maintainerDidCommitment,
    ));
    const activeMaintainer = (await simulator.getLedger()).maintainerRecords.lookup(
      candidate.keyId,
    );
    expect(activeMembership.status).toEqual(AuthorizationStatus.active);
    expect(activeMaintainer.status).toEqual(MaintainerStatus.active);
    expect((await simulator.getLedger()).activeMaintainerCount).toEqual(2n);

    const allMemberPolicy = labelToBytes32("policy:recovery:two-of-two");
    const allMemberPolicySequence = (await simulator.getLedger()).governanceActionCount;
    const allMemberPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        (await simulator.getLedger()).governancePolicyCommitment,
        allMemberPolicy, 2n, 2n, 2n, 2n,
      ), allMemberPolicySequence,
    );
    await expect((async () => (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey, allMemberPolicySignature,
      allMemberPolicy, 2n, 2n, 2n, 2n,
    )))()).rejects.toThrow(/non-conflicted removal quorum/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(allMemberPolicySequence);

    const suspendEvidenceHash = labelToBytes32("evidence:governed:suspend");
    const suspendActionSequence = (await simulator.getLedger()).governanceActionCount;
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
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
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        activeMembership.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );
    await expect((async () => (await simulator.suspendMaintainerMembership(
      candidate.keyId,
      candidate.publicKey,
      selfRemovalSignature,
      candidate.maintainerId,
      suspendEvidenceHash,
    )))()).rejects.toThrow(/own DID/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(suspendActionSequence);

    (await simulator.suspendMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      candidate.maintainerId,
      suspendEvidenceHash,
    ));

    const suspendedMembership = (await simulator.getMaintainerMembership(
      candidate.maintainerId,
    ));
    expect(suspendedMembership.status).toEqual(AuthorizationStatus.suspended);
    expect((await simulator.getLedger()).activeMaintainerCount).toEqual(1n);

    const revokeEvidenceHash = labelToBytes32("evidence:governed:revoke");
    const revokeActionSequence = (await simulator.getLedger()).governanceActionCount;
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        suspendedMembership.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      revokeActionSequence,
    );

    (await simulator.revokeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      candidate.maintainerId,
      revokeEvidenceHash,
    ));

    const revokedMembership = (await simulator.getMaintainerMembership(
      candidate.maintainerId,
    ));
    expect(revokedMembership.status).toEqual(AuthorizationStatus.revoked);
    expect(
      (await simulator.getLedger()).maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:governed:archive");
    const archiveActionSequence = (await simulator.getLedger()).governanceActionCount;
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        revokedMembership.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      archiveActionSequence,
    );

    (await simulator.archiveMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      candidate.maintainerId,
      archiveEvidenceHash,
    ));

    const archivedMembership = (await simulator.getMaintainerMembership(
      candidate.maintainerId,
    ));
    expect(archivedMembership.status).toEqual(AuthorizationStatus.archived);
    expect(
      (await simulator.getLedger()).maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.archived);
  });

  it("rejects an unregistered or cross-role evidence signature on maintainer enrollment", async () => {
    const registry = createInitializedRegistryFixture(62);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("signed-candidate", 63);
    const proof = await maintainerProposalProof(registry, candidate);
    const sign = async () => signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, (await simulator.getLedger()).governanceActionCount,
    );
    const propose = async (keyId: Uint8Array, evidenceSignature: typeof proof.evidenceSignature) =>
      (await simulator.proposeMaintainerMembership(
        bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(),
        candidate.maintainerId, candidate.maintainerDidCommitment,
        candidate.keyId, candidate.publicKey, candidate.policyId,
        candidate.trustLevel, candidate.evidenceHash,
        proof.verifierAuthorizationId, keyId, evidenceSignature,
      ));
    await expect((async () => (await simulator.getMaintainerProposalEvidence(candidate.maintainerId)))()).rejects.toThrow(/not registered/i);
    await expect(propose(labelToBytes32("wrong-evidence-verifier-key"), proof.evidenceSignature))
      .rejects.toThrow(/key id does not match/i);
    await expect(propose(proof.verifierKeyIdCommitment,
      signAuditorProposalEvidenceFromSeed(
        new Uint8Array(32).fill(97), registryId,
        FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
        proof.verifierKeyIdCommitment, proof.payloadHash,
      ))).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).maintainerMembershipCount).toBe(1n);
    const eventHash = await propose(proof.verifierKeyIdCommitment, proof.evidenceSignature);
    const evidence = (await simulator.getMaintainerProposalEvidence(candidate.maintainerId));
    expect(evidence.evidenceCommitment).toEqual(candidate.evidenceHash);
    expect(evidence.evidenceVerifierKeyIdCommitment).toEqual(proof.verifierKeyIdCommitment);
    expect(evidence.proposalGovernanceEventHash).toEqual(eventHash);
    await expect(propose(proof.verifierKeyIdCommitment, proof.evidenceSignature))
      .rejects.toThrow(/already exists/i);
  });

  it("rejects a nonidentity low-order maintainer key before it can join quorum", async () => {
    const registry = createInitializedRegistryFixture(164);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("low-order-candidate", 165);
    candidate.publicKey = {
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    };
    const proof = await maintainerProposalProof(registry, candidate);
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () => (await simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      candidate.maintainerId, candidate.maintainerDidCommitment,
      candidate.keyId, candidate.publicKey, candidate.policyId,
      candidate.trustLevel, candidate.evidenceHash,
      proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
    )))()).rejects.toThrow();
    await expect((async () => (await simulator.getMaintainerMembership(candidate.maintainerId)))()).rejects.toThrow();
  });

  it("rejects maintainer approval after its proposal evidence policy is superseded", async () => {
    const registry = createInitializedRegistryFixture(64);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const candidate = createMaintainerMembershipFixture("stale-governance", 65);
    const proof = await maintainerProposalProof(registry, candidate);
    (await simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_MAINTAINER_ACTION_KIND, proof.payloadHash, (await simulator.getLedger()).governanceActionCount,
      ),
      candidate.maintainerId, candidate.maintainerDidCommitment,
      candidate.keyId, candidate.publicKey, candidate.policyId,
      candidate.trustLevel, candidate.evidenceHash,
      proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    ));
    const proposalEvent = (await simulator.getMaintainerProposalEvidence(candidate.maintainerId)).proposalGovernanceEventHash;
    const oldPolicy = (await simulator.getLedger()).governancePolicyCommitment;
    const newPolicy = labelToBytes32("policy:maintainer:evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      oldPolicy, newPolicy, 2n, 1n, 1n, 1n,
    );
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, oldPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      newPolicy, 2n, 1n, 1n, 1n,
    ));
    const record = (await simulator.getMaintainerMembership(candidate.maintainerId));
    const approvalHash = computeUpdateMaintainerMembershipPayloadHash(
      candidate.maintainerId, record.lifecycleEventHash, candidate.evidenceHash,
    );
    await expect((async () => (await simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, newPolicy, AUTHORIZE_MAINTAINER_ACTION_KIND,
        approvalHash, (await simulator.getLedger()).governanceActionCount,
      ),
      candidate.maintainerId, candidate.evidenceHash,
    )))()).rejects.toThrow(/proposal evidence policy is not current/i);
    expect((await simulator.getMaintainerMembership(candidate.maintainerId)).status).toBe(AuthorizationStatus.proposed);
    expect((await simulator.getMaintainerProposalEvidence(candidate.maintainerId)).proposalGovernanceEventHash)
      .toEqual(proposalEvent);
  });

  it("rejects duplicate live maintainer identity enrollment and self-voted deactivation", async () => {
    const registry = createInitializedRegistryFixture(13);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const selfCandidate = createMaintainerMembershipFixture("self", 14);
    selfCandidate.maintainerDidCommitment = bootstrapMaintainer.didCommitment;
    const proposalProof = await maintainerProposalProof(registry, selfCandidate);

    const proposeActionSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeActionSequence,
    );

    await expect((async () =>
      (await simulator.proposeMaintainerMembership(
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
      )))()).rejects.toThrow(/already has a live membership/i);

    const selfActions = [
      {
        kind: SUSPEND_MAINTAINER_ACTION_KIND,
        invoke: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          (await simulator.suspendMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          )),
      },
      {
        kind: REVOKE_MAINTAINER_ACTION_KIND,
        invoke: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          (await simulator.revokeMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          )),
      },
      {
        kind: ARCHIVE_MAINTAINER_ACTION_KIND,
        invoke: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>, evidenceHash: Uint8Array) =>
          (await simulator.archiveMaintainerMembership(
            bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
            bootstrapMaintainer.maintainerId, evidenceHash,
          )),
      },
    ];
    for (const action of selfActions) {
      const sequence = (await simulator.getLedger()).governanceActionCount;
      const evidenceHash = labelToBytes32(`evidence:self-removal:${sequence}`);
      const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        action.kind,
        computeUpdateMaintainerMembershipPayloadHash(
          bootstrapMaintainer.maintainerId,
          (await simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)).lifecycleEventHash,
          evidenceHash,
        ),
        sequence,
      );
      await expect(action.invoke(signature, evidenceHash)).rejects.toThrow(/own DID/i);
      expect((await simulator.getLedger()).governanceActionCount).toBe(sequence);
      expect((await simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)).status)
        .toBe(AuthorizationStatus.active);
    }
  });

  it.each(["revoke", "archive"] as const)(
    "excludes an active maintainer from their own %s quorum",
    async (action) => {
      const registry = createInitializedRegistryFixture(73);
      const { simulator, registryId } = registry;
      const target = createMaintainerMembershipFixture(`self-${action}`, 74);
      await activateAdditionalMaintainer(registry, target);
      const kind = action === "revoke"
        ? REVOKE_MAINTAINER_ACTION_KIND : ARCHIVE_MAINTAINER_ACTION_KIND;
      const evidenceHash = labelToBytes32(`evidence:self-${action}`);
      const before = (await simulator.getLedger()).governanceActionCount;
      const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
        target.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        kind,
        computeUpdateMaintainerMembershipPayloadHash(
          target.maintainerId,
          (await simulator.getMaintainerMembership(target.maintainerId)).lifecycleEventHash,
          evidenceHash,
        ),
        before,
      );
      await expect((async () => {
        if (action === "revoke") {
          (await simulator.revokeMaintainerMembership(
            target.keyId, target.publicKey, signature, target.maintainerId, evidenceHash,
          ));
        } else {
          (await simulator.archiveMaintainerMembership(
            target.keyId, target.publicKey, signature, target.maintainerId, evidenceHash,
          ));
        }
      })()).rejects.toThrow(/own DID/i);
      expect((await simulator.getLedger()).governanceActionCount).toBe(before);
      expect((await simulator.getMaintainerMembership(target.maintainerId)).status)
        .toBe(AuthorizationStatus.active);
    },
  );

  it("atomically reduces policy and removes a target under the old 2-of-3 quorum", async () => {
    const registry = createInitializedRegistryFixture(75);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const second = createMaintainerMembershipFixture("recovery-second", 76);
    const target = createMaintainerMembershipFixture("recovery-target", 77);
    await activateAdditionalMaintainer(registry, second);
    await activateAdditionalMaintainer(registry, target);

    const twoOfThree = labelToBytes32("policy:recovery:two-of-three");
    const firstPolicy = (await simulator.getLedger()).governancePolicyCommitment;
    const policySequence = (await simulator.getLedger()).governanceActionCount;
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, firstPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
        computeUpdateMaintainerThresholdPolicyPayloadHash(
          firstPolicy, twoOfThree, 2n, 2n, 2n, 2n,
        ), policySequence,
      ),
      twoOfThree, 2n, 2n, 2n, 2n,
    ));

    const evidenceHash = labelToBytes32("evidence:recovery:remove-target");
    const removalPayload = computeUpdateMaintainerMembershipPayloadHash(
      target.maintainerId,
      (await simulator.getMaintainerMembership(target.maintainerId)).lifecycleEventHash,
      evidenceHash,
    );
    const removalSequence = (await simulator.getLedger()).governanceActionCount;
    const removalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfThree,
      SUSPEND_MAINTAINER_ACTION_KIND, removalPayload, removalSequence,
    );
    const coSigner = await createMaintainerCoAuthorizer(
      second, simulator, registryId, SUSPEND_MAINTAINER_ACTION_KIND,
      removalPayload, removalSequence,
    );
    await expect((async () => (await simulator.suspendMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, removalSignature,
      target.maintainerId, evidenceHash, [coSigner],
    )))()).rejects.toThrow(/non-conflicted removal quorum/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(removalSequence);
    expect((await simulator.getMaintainerMembership(target.maintainerId)).status)
      .toBe(AuthorizationStatus.active);

    const oneOfTwo = labelToBytes32("policy:recovery:one-of-two");
    const recoveryPayload = computeRecoverMaintainerMembershipPayloadHash(
      twoOfThree, oneOfTwo, 3n, 1n, 1n, 1n,
      target.maintainerId,
      (await simulator.getMaintainerMembership(target.maintainerId)).lifecycleEventHash,
      evidenceHash,
    );
    const recoverySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfThree,
      RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    const recoveryCoSigner = await createMaintainerCoAuthorizer(
      second, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    const targetCoSigner = await createMaintainerCoAuthorizer(
      target, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND,
      recoveryPayload, removalSequence,
    );
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [targetCoSigner],
    )))()).rejects.toThrow(/own DID/u);
    expect((await simulator.getLedger()).governanceActionCount).toBe(removalSequence);
    expect((await simulator.getLedger()).governancePolicyCommitment).toEqual(twoOfThree);
    expect((await simulator.getMaintainerMembership(target.maintainerId)).status)
      .toBe(AuthorizationStatus.active);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
    )))()).rejects.toThrow(/signer count must satisfy/u);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 2n, 2n, 2n,
      [recoveryCoSigner],
    )))()).rejects.toThrow(/non-conflicted removal quorum/u);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 4n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )))()).rejects.toThrow(/Policy version must increase by one/u);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, twoOfThree, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )))()).rejects.toThrow(/must not reuse a historical snapshot/u);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, labelToBytes32("policy:recovery:tampered"),
      3n, 1n, 1n, 1n, [recoveryCoSigner],
    )))()).rejects.toThrow(/invalid jubjub schnorr signature/iu);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, labelToBytes32("evidence:recovery:tampered"),
      oneOfTwo, 3n, 1n, 1n, 1n, [recoveryCoSigner],
    )))()).rejects.toThrow(/invalid jubjub schnorr signature/iu);
    expect((await simulator.getLedger()).governanceActionCount).toBe(removalSequence);

    const recoveryEvent = (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    ));
    expect((await simulator.getLedger()).governancePolicyCommitmentsByVersion.lookup(2n))
      .toEqual(twoOfThree);
    expect((await simulator.getLedger()).lastGovernanceEventHash).toEqual(recoveryEvent);
    expect((await simulator.getLedger()).activeMaintainerCount).toBe(2n);
    expect((await simulator.getLedger()).emergencyMaintainerThreshold).toBe(1n);
    expect((await simulator.getLedger()).governancePolicyCommitment).toEqual(oneOfTwo);
    expect((await simulator.getMaintainerMembership(target.maintainerId)).lifecycleEventHash)
      .toEqual(recoveryEvent);
    expect((await simulator.getLedger()).governanceActionCount).toBe(removalSequence + 1n);
    expect((await simulator.getLedger()).governancePolicyEffectiveFromByVersion.lookup(3n))
      .toBe(removalSequence + 1n);
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, recoverySignature,
      target.maintainerId, evidenceHash, oneOfTwo, 3n, 1n, 1n, 1n,
      [recoveryCoSigner],
    )))()).rejects.toThrow(/must be active to recover/u);
  });
  it("requires the higher old emergency quorum for atomic recovery", async () => {
    const registry = createInitializedRegistryFixture(81);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const second = createMaintainerMembershipFixture("recovery-emergency-second", 82);
    const third = createMaintainerMembershipFixture("recovery-emergency-third", 83);
    const target = createMaintainerMembershipFixture("recovery-emergency-target", 84);
    for (const candidate of [second, third, target]) await activateAdditionalMaintainer(registry, candidate);
    const initialPolicy = (await simulator.getLedger()).governancePolicyCommitment;
    const twoOfFour = labelToBytes32("policy:recovery:two-of-four");
    const revisionPayload = computeUpdateMaintainerThresholdPolicyPayloadHash(
      initialPolicy, twoOfFour, 2n, 2n, 3n, 2n,
    );
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator, bootstrapMaintainer.seed, registryId,
        initialPolicy, UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
        revisionPayload, (await simulator.getLedger()).governanceActionCount),
      twoOfFour, 2n, 2n, 3n, 2n,
    ));
    const nextPolicy = labelToBytes32("policy:recovery:two-of-three");
    const evidenceHash = labelToBytes32("evidence:recovery:emergency");
    const actionSequence = (await simulator.getLedger()).governanceActionCount;
    const recoveryPayload = computeRecoverMaintainerMembershipPayloadHash(
      twoOfFour, nextPolicy, 3n, 2n, 2n, 2n,
      target.maintainerId,
      (await simulator.getMaintainerMembership(target.maintainerId)).lifecycleEventHash,
      evidenceHash,
    );
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, twoOfFour,
      RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const secondVote = await createMaintainerCoAuthorizer(
      second, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const thirdVote = await createMaintainerCoAuthorizer(
      third, simulator, registryId, RECOVER_MAINTAINER_ACTION_KIND, recoveryPayload, actionSequence,
    );
    const recover = async (votes: MaintainerCoAuthorizer[]) => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      target.maintainerId, evidenceHash, nextPolicy, 3n, 2n, 2n, 2n, votes,
    ));
    await expect(recover([secondVote])).rejects.toThrow(/signer count must satisfy/u);
    expect((await simulator.getLedger()).governanceActionCount).toBe(actionSequence);
    expect((await simulator.getMaintainerMembership(target.maintainerId)).status).toBe(AuthorizationStatus.active);
    await recover([secondVote, thirdVote]);
    expect((await simulator.getLedger()).activeMaintainerCount).toBe(3n);
    expect((await simulator.getMaintainerMembership(target.maintainerId)).status).toBe(AuthorizationStatus.suspended);
  });
  it("rejects atomic recovery of the last active maintainer", async () => {
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = createInitializedRegistryFixture(85);
    const target = (await simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId));
    const evidenceHash = labelToBytes32("evidence:recovery:last");
    const nextPolicy = labelToBytes32("policy:recovery:last");
    const currentPolicy = (await simulator.getLedger()).governancePolicyCommitment;
    const payload = computeRecoverMaintainerMembershipPayloadHash(
      currentPolicy, nextPolicy, 2n, 1n, 1n, 1n,
      bootstrapMaintainer.maintainerId, target.lifecycleEventHash, evidenceHash,
    );
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, currentPolicy,
      RECOVER_MAINTAINER_ACTION_KIND, payload, (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () => (await simulator.recoverMaintainerMembership(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      bootstrapMaintainer.maintainerId, evidenceHash, nextPolicy, 2n, 1n, 1n, 1n,
    )))()).rejects.toThrow(/last active maintainer/u);
  });
  for (const role of ["issuer", "verifier", "auditor", "recognition"] as const) {
    it(`rejects a maintainer's own ${role} approval without consuming the action sequence`, async () => {
      const registry = createInitializedRegistryFixture(31);
      const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
      const sign = async (kind: Uint8Array, payloadHash: Uint8Array) =>
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed, registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          kind, payloadHash, (await simulator.getLedger()).governanceActionCount,
        );
      const scenario = await (async () => {
        if (role === "issuer") {
          const item = createIssuerAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = await issuerProposalProof(registry, item, await registerIssuerEvidenceVerifier(registry));
          (await simulator.proposeIssuerAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.resourceType, item.resourceId,
            item.policyId, item.statusPolicyBindingCommitment, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          ));
          return {
            kind: AUTHORIZE_ISSUER_ACTION_KIND,
            payloadHash: computeUpdateIssuerAuthorizationPayloadHash(
              item.authorizationId, (await simulator.getIssuerAuthorization(item.authorizationId)).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              (await simulator.authorizeIssuerAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              )),
            status: async () => (await simulator.getIssuerAuthorization(item.authorizationId)).status,
          };
        }
        if (role === "verifier") {
          const item = createVerifierAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = await verifierProposalProof(registry, item);
          (await simulator.proposeVerifierAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(PROPOSE_VERIFIER_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.requestResourceId,
            item.allowedAttributeSetCommitment, item.allowedPredicateSetCommitment,
            item.disclosureLevelCommitment, item.policyId, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          ));
          return {
            kind: AUTHORIZE_VERIFIER_ACTION_KIND,
            payloadHash: computeUpdateVerifierAuthorizationPayloadHash(
              item.authorizationId, (await simulator.getVerifierAuthorization(item.authorizationId)).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              (await simulator.authorizeVerifierAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              )),
            status: async () => (await simulator.getVerifierAuthorization(item.authorizationId)).status,
          };
        }
        if (role === "auditor") {
          const item = createAuditorAuthorizationFixture("self-vote");
          item.subjectDidCommitment = bootstrapMaintainer.didCommitment;
          const proof = await auditorProposalProof(registry, item);
          (await simulator.proposeAuditorAuthorization(
            bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash),
            item.authorizationId, item.subjectDidCommitment, item.requestResourceId,
            item.allowedAttributeSetCommitment, item.allowedPredicateSetCommitment,
            item.disclosureLevelCommitment, item.policyId, item.trustLevel, item.evidenceHash,
            proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
          ));
          return {
            kind: AUTHORIZE_AUDITOR_ACTION_KIND,
            payloadHash: computeUpdateAuditorAuthorizationPayloadHash(
              item.authorizationId, (await simulator.getAuditorAuthorization(item.authorizationId)).lifecycleEventHash,
              item.evidenceHash,
            ),
            authorize: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
              (await simulator.authorizeAuditorAuthorization(
                bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
                item.authorizationId, item.evidenceHash,
              )),
            status: async () => (await simulator.getAuditorAuthorization(item.authorizationId)).status,
          };
        }
        const item = createRecognitionFixture("self-vote");
        item.recognizedAuthorityDidCommitment = bootstrapMaintainer.didCommitment;
        const proof = await recognitionProposalProof(registry, item, item.evidenceHash);
        (await simulator.proposeRecognition(
          bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(PROPOSE_RECOGNITION_ACTION_KIND, proof.payloadHash),
          item.recognitionId, item.recognizedAuthorityDidCommitment, item.recognizedRegistryId,
          item.scopeResourceType, item.scopeResourceId, item.policyId, item.trustLevel, item.evidenceHash,
          proof.verifierAuthorizationId, proof.verifierKeyIdCommitment, proof.evidenceSignature,
        ));
        return {
          kind: AUTHORIZE_RECOGNITION_ACTION_KIND,
          payloadHash: computeUpdateRecognitionPayloadHash(
            item.recognitionId, (await simulator.getRecognition(item.recognitionId)).lifecycleEventHash,
            item.evidenceHash,
          ),
          authorize: async (signature: ReturnType<typeof signFixtureDeploymentBoundActionFromSeed>) =>
            (await simulator.authorizeRecognition(
              bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
              item.recognitionId, item.evidenceHash,
            )),
          status: async () => (await simulator.getRecognition(item.recognitionId)).status,
        };
      })();
      const sequence = (await simulator.getLedger()).governanceActionCount;
      await expect(scenario.authorize(await sign(scenario.kind, scenario.payloadHash))).rejects.toThrow(/own DID/i);
      expect((await simulator.getLedger()).governanceActionCount).toBe(sequence);
      expect(await scenario.status()).toBe(AuthorizationStatus.proposed);
    });
  }

  it("records a signed generic audit event without a lifecycle transition", async () => {
    const registryId = labelToBytes32("registry:midnight");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:midnight:v1");
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
    const actionSequence = (await simulator.getLedger()).governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyFixtureDeploymentBoundAction(simulator,
        bootstrapPublicKey,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        actionKind,
        actionPayloadHash,
        actionSequence,
        signature,
      ),
    ).toBe(true);

    const lifecycleSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      actionPayloadHash,
      actionSequence,
    );
    await expect((async () => (await simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      lifecycleSignature,
      actionPayloadHash,
    )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(actionSequence);

    const eventHash = (await simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      actionPayloadHash,
    ));
    const state = (await simulator.getLedger());

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

  it("updates quorum thresholds and enforces scoped multi-maintainer execution", async () => {
    const registry = createInitializedRegistryFixture(15);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const secondMaintainer = createMaintainerMembershipFixture("second", 16);
    const proposalProof = await maintainerProposalProof(registry, secondMaintainer);

    const proposeMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeMaintainerSequence,
    );
    (await simulator.proposeMaintainerMembership(
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
    ));

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const authorizeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        (await simulator.getMaintainerMembership(secondMaintainer.maintainerId))
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    (await simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    ));

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const activateMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        (await simulator.getMaintainerMembership(secondMaintainer.maintainerId))
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    (await simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    ));

    const conflictedEvidenceHash = labelToBytes32("evidence:self:second-signer");
    const conflictedSequence = (await simulator.getLedger()).governanceActionCount;
    const conflictedPayloadHash = computeUpdateMaintainerMembershipPayloadHash(
      bootstrapMaintainer.maintainerId,
      (await simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)).lifecycleEventHash,
      conflictedEvidenceHash,
    );
    const nonconflictedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      secondMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND, conflictedPayloadHash, conflictedSequence,
    );
    const conflictedCoSigner: MaintainerCoAuthorizer = {
      keyId: bootstrapMaintainer.keyId,
      publicKey: bootstrapPublicKey,
      signature: signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        SUSPEND_MAINTAINER_ACTION_KIND, conflictedPayloadHash, conflictedSequence,
      ),
    };
    await expect((async () => (await simulator.suspendMaintainerMembership(
      secondMaintainer.keyId, secondMaintainer.publicKey, nonconflictedSignature,
      bootstrapMaintainer.maintainerId, conflictedEvidenceHash, [conflictedCoSigner],
    )))()).rejects.toThrow(/own DID/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(conflictedSequence);

    const selfActivation = createIssuerAuthorizationFixture("self-activation");
    selfActivation.subjectDidCommitment = bootstrapMaintainer.didCommitment;
    const selfActivationProof = await issuerProposalProof(
      registry, selfActivation, await registerIssuerEvidenceVerifier(registry),
    );
    const signAsSecond = async (kind: Uint8Array, payloadHash: Uint8Array) =>
      signFixtureDeploymentBoundActionFromSeed(simulator,
        secondMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        kind, payloadHash, (await simulator.getLedger()).governanceActionCount,
      );
    (await simulator.proposeIssuerAuthorization(
      secondMaintainer.keyId, secondMaintainer.publicKey,
      await signAsSecond(PROPOSE_ISSUER_ACTION_KIND, selfActivationProof.payloadHash),
      selfActivation.authorizationId, selfActivation.subjectDidCommitment,
      selfActivation.resourceType, selfActivation.resourceId, selfActivation.policyId,
      selfActivation.statusPolicyBindingCommitment, selfActivation.trustLevel,
      selfActivation.evidenceHash, selfActivationProof.verifierAuthorizationId,
      selfActivationProof.verifierKeyIdCommitment, selfActivationProof.evidenceSignature,
    ));
    const authorizePayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      selfActivation.authorizationId,
      (await simulator.getIssuerAuthorization(selfActivation.authorizationId)).lifecycleEventHash,
      selfActivation.evidenceHash,
    );
    (await simulator.authorizeIssuerAuthorization(
      secondMaintainer.keyId, secondMaintainer.publicKey,
      await signAsSecond(AUTHORIZE_ISSUER_ACTION_KIND, authorizePayloadHash),
      selfActivation.authorizationId, selfActivation.evidenceHash,
    ));
    const activatePayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      selfActivation.authorizationId,
      (await simulator.getIssuerAuthorization(selfActivation.authorizationId)).lifecycleEventHash,
      selfActivation.evidenceHash,
    );
    const activateSequence = (await simulator.getLedger()).governanceActionCount;
    await expect((async () => (await simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        ACTIVATE_ISSUER_ACTION_KIND, activatePayloadHash, activateSequence,
      ),
      selfActivation.authorizationId, selfActivation.evidenceHash,
    )))()).rejects.toThrow(/own DID/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(activateSequence);
    expect((await simulator.getIssuerAuthorization(selfActivation.authorizationId)).status)
      .toBe(AuthorizationStatus.authorized);

    const thirdMaintainer = createMaintainerMembershipFixture("third", 19);
    await activateAdditionalMaintainer(registry, thirdMaintainer);
    expect((await simulator.getLedger()).activeMaintainerCount).toBe(3n);

    const invalidThresholdPolicySequence = (await simulator.getLedger()).governanceActionCount;
    const invalidThresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        (await simulator.getLedger()).governancePolicyCommitment,
        labelToBytes32("policy:midnight:v2"),
        2n,
        4n,
        1n,
        1n,
      ),
      invalidThresholdPolicySequence,
    );
    await expect((async () =>
      (await simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        invalidThresholdPolicySignature,
        labelToBytes32("policy:midnight:v2"),
        2n,
        4n,
        1n,
        1n,
      )))()).rejects.toThrow(/may not exceed active maintainer count/i);

    const thresholdPolicySequence = (await simulator.getLedger()).governanceActionCount;
    const thresholdPolicyPayloadHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      (await simulator.getLedger()).governancePolicyCommitment,
      labelToBytes32("policy:midnight:v2"),
      2n,
      2n,
      1n,
      2n,
    );
    const thresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      thresholdPolicyPayloadHash,
      thresholdPolicySequence,
    );
    await expect((async () =>
      (await simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("policy:midnight:unsigned"),
        2n,
        2n,
        1n,
        2n,
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect((async () =>
      (await simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        (await simulator.getLedger()).governancePolicyCommitment,
        2n,
        2n,
        1n,
        2n,
      )))()).rejects.toThrow(/must not reuse/i);
    await expect((async () =>
      (await simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        new Uint8Array(32),
        2n,
        2n,
        1n,
        2n,
      )))()).rejects.toThrow(/Policy commitment must be set/);
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:midnight:v2"),
      2n,
      2n,
      1n,
      2n,
    ));

    expect((await simulator.getLedger()).maintainerThreshold).toEqual(2n);
    expect((await simulator.getLedger()).emergencyMaintainerThreshold).toEqual(1n);
    expect((await simulator.getLedger()).archivalMaintainerThreshold).toEqual(2n);
    expect((await simulator.getLedger()).governancePolicyVersion).toEqual(2n);

    const removalEvidenceHash = labelToBytes32("evidence:nonself:threshold-removal");
    const removalSequence = (await simulator.getLedger()).governanceActionCount;
    const removalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      secondMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        bootstrapMaintainer.maintainerId,
        (await simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)).lifecycleEventHash,
        removalEvidenceHash,
      ),
      removalSequence,
    );
    await expect((async () => (await simulator.suspendMaintainerMembership(
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      removalSignature,
      bootstrapMaintainer.maintainerId,
      removalEvidenceHash,
    )))()).rejects.toThrow(/non-conflicted removal quorum/i);
    expect((await simulator.getLedger()).governanceActionCount).toBe(removalSequence);
    expect(Buffer.from((await simulator.getLedger()).governancePolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:midnight:v2")),
    );
    expect(Buffer.from((await simulator.getLedger()).lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:midnight:v1")),
    );
    expect(
      Buffer.from((await simulator.getLedger()).governancePolicyCommitmentsByVersion.lookup(1n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:midnight:v1")));
    expect(
      Buffer.from((await simulator.getLedger()).governancePolicyCommitmentsByVersion.lookup(2n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:midnight:v2")));
    expect((await simulator.getLedger()).governancePolicyEffectiveFromByVersion.lookup(2n)).toEqual(
      thresholdPolicySequence + 1n,
    );

    await expect((async () =>
      (await simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("unused-policy-commitment"),
        2n,
        2n,
        1n,
        2n,
      )))()).rejects.toThrow(/version must increase/i);

    const auditPayload = labelToBytes32("quorum:raw-order-rejection");
    const auditSequence = (await simulator.getLedger()).governanceActionCount;
    const auditPolicyCommitment = (await simulator.getLedger()).governancePolicyCommitment;
    const auditSigners = [
      { keyId: bootstrapMaintainer.keyId, publicKey: bootstrapPublicKey, seed: bootstrapMaintainer.seed },
      { keyId: secondMaintainer.keyId, publicKey: secondMaintainer.publicKey, seed: secondMaintainer.seed },
    ].sort((left, right) => compareMaintainerKeyIds(left.keyId, right.keyId)).reverse()
      .map(({ keyId, publicKey, seed }) => ({
        keyId,
        publicKey,
        signature: signFixtureDeploymentBoundActionFromSeed(simulator,
          seed, registryId, auditPolicyCommitment,
          GENERIC_AUDIT_ACTION_KIND, auditPayload, auditSequence),
      }));
    const emptySigner = {
      keyId: new Uint8Array(32),
      publicKey: { x: 0n, y: 0n },
      signature: { announcement: { x: 0n, y: 0n }, response: 0n },
    };
    await expect(simulator.contract.impureCircuits.authorizeMaintainerAuditEvent(
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
    )).rejects.toThrow(/Maintainer signer keys must be sorted/);
    await expect(simulator.contract.impureCircuits.authorizeMaintainerAuditEvent(
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
    )).rejects.toThrow(/Maintainer signer keys must be sorted/);
    expect((await simulator.getLedger()).governanceActionCount).toBe(auditSequence);

    const issuer = createIssuerAuthorizationFixture("quorum");
    const proposedEvidenceHash = labelToBytes32("evidence:quorum:issuer:propose");
    const issuerProof = await issuerProposalProof(
      registry, { ...issuer, evidenceHash: proposedEvidenceHash },
      await registerIssuerEvidenceVerifier(registry, secondMaintainer),
    );
    const proposeIssuerPayloadHash = issuerProof.payloadHash;

    const singleSignerSequence = (await simulator.getLedger()).governanceActionCount;
    const singleSignerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      singleSignerSequence,
    );
    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/must satisfy the action threshold/i);

    const proposeIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const secondIssuerProposer = await createMaintainerCoAuthorizer(
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
      labelToBytes32("policy:midnight:v1"),
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);
    (await simulator.proposeIssuerAuthorization(
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
    ));
    expect(Buffer.from((await simulator.getLedger()).lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:midnight:v2")),
    );

    const authorizeIssuerEvidenceHash = proposedEvidenceHash;
    const authorizeIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      (await simulator.getIssuerAuthorization(issuer.authorizationId)).lifecycleEventHash,
      authorizeIssuerEvidenceHash,
    );
    const authorizeIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const authorizeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    const secondIssuerAuthorizer = await createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    (await simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeIssuerSignature,
      issuer.authorizationId,
      authorizeIssuerEvidenceHash,
      [secondIssuerAuthorizer],
    ));

    const activateIssuerEvidenceHash = proposedEvidenceHash;
    const activateIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      (await simulator.getIssuerAuthorization(issuer.authorizationId)).lifecycleEventHash,
      activateIssuerEvidenceHash,
    );
    const activateIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const activateIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    const secondIssuerActivator = await createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    (await simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateIssuerSignature,
      issuer.authorizationId,
      activateIssuerEvidenceHash,
      [secondIssuerActivator],
    ));

    const suspendedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:suspend",
    );
    const suspendIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const suspendIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuer.authorizationId,
        (await simulator.getIssuerAuthorization(issuer.authorizationId)).lifecycleEventHash,
        suspendedIssuerEvidenceHash,
      ),
      suspendIssuerSequence,
    );
    (await simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendIssuerSignature,
      issuer.authorizationId,
      suspendedIssuerEvidenceHash,
    ));

    expect((await simulator.getIssuerAuthorization(issuer.authorizationId)).status).toEqual(
      AuthorizationStatus.suspended,
    );

    const archivedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:archive",
    );
    const archiveIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      (await simulator.getIssuerAuthorization(issuer.authorizationId)).lifecycleEventHash,
      archivedIssuerEvidenceHash,
    );
    const archiveIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const archiveIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    await expect((async () =>
      (await simulator.archiveIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        archiveIssuerSignature,
        issuer.authorizationId,
        archivedIssuerEvidenceHash,
      )))()).rejects.toThrow(/must satisfy the action threshold/i);

    const secondIssuerArchiver = await createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    (await simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveIssuerSignature,
      issuer.authorizationId,
      archivedIssuerEvidenceHash,
      [secondIssuerArchiver],
    ));

    expect((await simulator.getIssuerAuthorization(issuer.authorizationId)).status).toEqual(
      AuthorizationStatus.archived,
    );
  }, 20_000);

  it("rejects duplicate maintainer signers before quorum execution", async () => {
    const registry = createInitializedRegistryFixture(17);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const secondMaintainer = createMaintainerMembershipFixture("duplicate", 18);
    const proposalProof = await maintainerProposalProof(registry, secondMaintainer);

    const proposeMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      proposalProof.payloadHash,
      proposeMaintainerSequence,
    );
    (await simulator.proposeMaintainerMembership(
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
    ));

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const authorizeMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        (await simulator.getMaintainerMembership(secondMaintainer.maintainerId))
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    (await simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    ));

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = (await simulator.getLedger()).governanceActionCount;
    const activateMaintainerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        (await simulator.getMaintainerMembership(secondMaintainer.maintainerId))
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    (await simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    ));

    await activateAdditionalMaintainer(registry, createMaintainerMembershipFixture("third-duplicate", 20));

    const thresholdPolicySequence = (await simulator.getLedger()).governanceActionCount;
    const thresholdPolicySignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        (await simulator.getLedger()).governancePolicyCommitment,
        labelToBytes32("policy:midnight:v2"),
        2n,
        2n,
        1n,
        1n,
      ),
      thresholdPolicySequence,
    );
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:midnight:v2"),
      2n,
      2n,
      1n,
      1n,
    ));

    const issuer = createIssuerAuthorizationFixture("duplicate-quorum");
    const proposedEvidenceHash = labelToBytes32(
      "evidence:duplicate:issuer:propose",
    );
    const issuerProof = await issuerProposalProof(
      registry, { ...issuer, evidenceHash: proposedEvidenceHash },
      await registerIssuerEvidenceVerifier(registry, secondMaintainer),
    );
    const proposeIssuerPayloadHash = issuerProof.payloadHash;
    const proposeIssuerSequence = (await simulator.getLedger()).governanceActionCount;
    const proposeIssuerSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
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
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposeIssuerPayloadHash,
        proposeIssuerSequence,
      ),
    };

    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/duplicate key ID/u);
    expect((await simulator.getLedger()).governanceActionCount).toBe(proposeIssuerSequence);
  });

  it("does not count two maintainer IDs controlled by one public key as a quorum", async () => {
    const registry = createInitializedRegistryFixture(21);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const duplicateKeyMaintainer = {
      ...createMaintainerMembershipFixture("shared-key", 22),
      publicKey: bootstrapPublicKey,
      seed: bootstrapMaintainer.seed,
    };
    await activateAdditionalMaintainer(registry, duplicateKeyMaintainer);
    await activateAdditionalMaintainer(registry, createMaintainerMembershipFixture("independent-key", 23));

    const nextPolicy = labelToBytes32("policy:shared-key:v2");
    const policyPayload = computeUpdateMaintainerThresholdPolicyPayloadHash(
      (await simulator.getLedger()).governancePolicyCommitment, nextPolicy, 2n, 2n, 1n, 1n,
    );
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyPayload,
        (await simulator.getLedger()).governanceActionCount),
      nextPolicy, 2n, 2n, 1n, 1n,
    ));

    const payload = labelToBytes32("audit:shared-maintainer-key");
    const sequence = (await simulator.getLedger()).governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      GENERIC_AUDIT_ACTION_KIND, payload, sequence,
    );
    const duplicateSigner = await createMaintainerCoAuthorizer(
      duplicateKeyMaintainer, simulator, registryId, GENERIC_AUDIT_ACTION_KIND,
      payload, sequence,
    );
    await expect((async () => (await simulator.authorizeMaintainerAuditEvent(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature, payload, [duplicateSigner],
    )))()).rejects.toThrow(/public keys must be distinct/u);
    expect((await simulator.getLedger()).governanceActionCount).toBe(sequence);
  });

  it("bootstraps before any maintainer action and rejects tampered authorization", async () => {
    const registryId = labelToBytes32("registry:midnight");
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
      governancePolicyCommitment: labelToBytes32("policy:midnight:v1"),
      maintainerId: bootstrapMaintainer.maintainerId,
      maintainerDidCommitment: bootstrapMaintainer.didCommitment,
      maintainerKeyId: bootstrapMaintainer.keyId,
      maintainerPublicKey: bootstrapPublicKey,
      maintainerThreshold: 1n,
    });
    expect((await simulator.getLedger()).initialized).toBe(true);

    const actionSequence = (await simulator.getLedger()).governanceActionCount;
    const validSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
    const tamperedSignature = {
      ...validSignature,
      response: validSignature.response + 1n,
    };

    await expect((async () =>
      (await simulator.authorizeMaintainerAuditEvent(
        labelToBytes32("maintainer:wrong"),
        bootstrapPublicKey,
        validSignature,
        actionPayloadHash,
      )))()).rejects.toThrow(/not registered/i);

    await expect((async () =>
      (await simulator.authorizeMaintainerAuditEvent(
        bootstrapMaintainer.keyId,
        deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
        validSignature,
        actionPayloadHash,
      )))()).rejects.toThrow(/does not match the registered key/i);

    await expect((async () =>
      (await simulator.authorizeMaintainerAuditEvent(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        actionPayloadHash,
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);
  });

  it("creates and queries an active issuer authorization by id and scope", async () => {
    const registry = createInitializedRegistryFixture(17);
    const { simulator } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("birth");
    const eventHash = await activateIssuerAuthorizationFixture(registry, issuerAuthorization);
    const state = (await simulator.getLedger());
    const recordById = (await simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    ));
    const recordByScope = (await simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    ));

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
    expect(async () =>
      (await simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )),
    ).not.toThrow();
  });

  it("requires issuer proposal evidence from the registered active verifier for the exact payload", async () => {
    const registry = createInitializedRegistryFixture(18);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuer = createIssuerAuthorizationFixture("evidence-bound");
    const verifier = await registerIssuerEvidenceVerifier(registry);
    const proof = await issuerProposalProof(registry, issuer, verifier);
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    const propose = async (
      fields: IssuerFixture = issuer,
      keyId = proof.verifierKeyIdCommitment,
      evidenceSignature = proof.evidenceSignature,
    ) => (await simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
      fields.authorizationId, fields.subjectDidCommitment, fields.resourceType,
      fields.resourceId, fields.policyId, fields.statusPolicyBindingCommitment,
      fields.trustLevel, fields.evidenceHash,
      proof.verifierAuthorizationId, keyId, evidenceSignature,
    ));

    await expect(propose(issuer, labelToBytes32("verifier:key:wrong")))
      .rejects.toThrow(/key id does not match/i);
    await expect(propose({ ...issuer, subjectDidCommitment: labelToBytes32("did:issuer:altered") }))
      .rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect(propose({ ...issuer, resourceId: labelToBytes32("resource:altered") }))
      .rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect(propose({ ...issuer, evidenceHash: labelToBytes32("evidence:altered") }))
      .rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect(propose(issuer, proof.verifierKeyIdCommitment, {
      ...proof.evidenceSignature, response: 0n,
    })).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).issuerAuthorizationCount).toEqual(0n);

    const suspendPayload = computeUpdateEvidenceVerifierKeyPayloadHash(
      verifier.authorizationId,
      (await simulator.getEvidenceVerifierKey(verifier.authorizationId)).lifecycleEventHash,
      labelToBytes32("verifier:suspended"),
    );
    (await simulator.suspendEvidenceVerifierKey(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND, suspendPayload,
        (await simulator.getLedger()).governanceActionCount,
      ),
      verifier.authorizationId, labelToBytes32("verifier:suspended"),
    ));
    await expect(propose()).rejects.toThrow(/evidence verifier key is not active/i);
    expect((await simulator.getLedger()).issuerAuthorizationCount).toEqual(0n);
  });

  it.each(["suspended-key-at-approval", "superseded-policy-at-activation"] as const)(
    "rejects issuer lifecycle transition with %s evidence",
    async (scenario) => {
      const registry = createInitializedRegistryFixture(39);
      const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
      const issuer = createIssuerAuthorizationFixture(scenario);
      const verifier = await registerIssuerEvidenceVerifier(registry);
      const proof = await issuerProposalProof(registry, issuer, verifier);
      const signAction = async (kind: Uint8Array, payloadHash: Uint8Array) =>
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed, registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          kind, payloadHash, (await simulator.getLedger()).governanceActionCount,
        );

      (await simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId, bootstrapPublicKey,
        await signAction(PROPOSE_ISSUER_ACTION_KIND, proof.payloadHash),
        issuer.authorizationId, issuer.subjectDidCommitment, issuer.resourceType,
        issuer.resourceId, issuer.policyId, issuer.statusPolicyBindingCommitment,
        issuer.trustLevel, issuer.evidenceHash,
        proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
        proof.evidenceSignature,
      ));

      const signIssuerTransition = async (kind: Uint8Array) => signAction(
        kind,
        computeUpdateIssuerAuthorizationPayloadHash(
          issuer.authorizationId,
          (await simulator.getIssuerAuthorization(issuer.authorizationId)).lifecycleEventHash,
          issuer.evidenceHash,
        ),
      );
      if (scenario === "superseded-policy-at-activation") {
        (await simulator.authorizeIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          await signIssuerTransition(AUTHORIZE_ISSUER_ACTION_KIND),
          issuer.authorizationId, issuer.evidenceHash,
        ));
        const nextPolicy = labelToBytes32("policy:issuer:next");
        (await simulator.updateMaintainerThresholdPolicy(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          await signAction(
            UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
            computeUpdateMaintainerThresholdPolicyPayloadHash(
              (await simulator.getLedger()).governancePolicyCommitment,
              nextPolicy, 2n, 1n, 1n, 1n,
            ),
          ),
          nextPolicy, 2n, 1n, 1n, 1n,
        ));
      } else {
        const suspendEvidence = labelToBytes32("evidence:verifier:suspend-after-proposal");
        (await simulator.suspendEvidenceVerifierKey(
          bootstrapMaintainer.keyId, bootstrapPublicKey,
          await signAction(
            SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
            computeUpdateEvidenceVerifierKeyPayloadHash(
              verifier.authorizationId,
              (await simulator.getEvidenceVerifierKey(verifier.authorizationId)).lifecycleEventHash,
              suspendEvidence,
            ),
          ),
          verifier.authorizationId, suspendEvidence,
        ));
      }

      const sequence = (await simulator.getLedger()).governanceActionCount;
      const eventHash = (await simulator.getLedger()).lastGovernanceEventHash;
      const kind = scenario === "superseded-policy-at-activation"
        ? ACTIVATE_ISSUER_ACTION_KIND : AUTHORIZE_ISSUER_ACTION_KIND;
      const signature = await signIssuerTransition(kind);
      await expect((async () => scenario === "superseded-policy-at-activation"
        ? (await simulator.activateIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
          issuer.authorizationId, issuer.evidenceHash,
        ))
        : (await simulator.authorizeIssuerAuthorization(
          bootstrapMaintainer.keyId, bootstrapPublicKey, signature,
          issuer.authorizationId, issuer.evidenceHash,
        )))()).rejects.toThrow(scenario === "superseded-policy-at-activation"
          ? /proposal evidence policy is not current/i
          : /evidence verifier key is not active/i);
      expect((await simulator.getLedger()).governanceActionCount).toBe(sequence);
      expect((await simulator.getLedger()).lastGovernanceEventHash).toEqual(eventHash);
      expect((await simulator.getIssuerAuthorization(issuer.authorizationId)).status).toEqual(
        scenario === "superseded-policy-at-activation"
          ? AuthorizationStatus.authorized : AuthorizationStatus.proposed,
      );
    },
  );

  it("moves an issuer authorization through proposed, authorized, and active states", async () => {
    const registry = createInitializedRegistryFixture(19);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("application");
    const proposalEvidenceHash = labelToBytes32("evidence:application:propose");
    const proposalProof = await issuerProposalProof(
      registry, { ...issuerAuthorization, evidenceHash: proposalEvidenceHash },
      await registerIssuerEvidenceVerifier(registry),
    );
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposalProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/issuer status policy binding commitment must be set/i);
    const substitutedPolicyProof = await issuerProposalProof(registry, {
      ...issuerAuthorization,
      evidenceHash: proposalEvidenceHash,
      statusPolicyBindingCommitment: labelToBytes32("status-policy:substituted"),
    }, await registerIssuerEvidenceVerifier(registry));
    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);
    const proposalEventHash = (await simulator.proposeIssuerAuthorization(
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
    ));
    const proposedRecord = (await simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    ));
    const proposalEvidence = (await simulator.getIssuerProposalEvidence(
      issuerAuthorization.authorizationId,
    ));

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
    expect((await simulator.getLedger()).issuerAuthorizationCount).toEqual(1n);
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(proposedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(proposalEventHash),
    );
    await expect((async () =>
      (await simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )))()).rejects.toThrow(/not active/i);

    const mismatchedEvidenceHash = labelToBytes32("evidence:application:mismatched");
    const mismatchedAuthorizationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        mismatchedEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () =>
      (await simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        mismatchedAuthorizationSignature,
        issuerAuthorization.authorizationId,
        mismatchedEvidenceHash,
      )))()).rejects.toThrow(/must match the proposed application/i);

    const authorizationEvidenceHash = proposalEvidenceHash;
    const authorizationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        authorizationEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    const authorizationEventHash = (await simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizationSignature,
      issuerAuthorization.authorizationId,
      authorizationEvidenceHash,
    ));
    const authorizedRecord = (await simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    ));

    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(Buffer.from(authorizedRecord.statusPolicyBindingCommitment)).toEqual(
      Buffer.from(issuerAuthorization.statusPolicyBindingCommitment),
    );
    expect(authorizedRecord.authorizedAtSequence).toBeGreaterThan(
      proposedRecord.proposedAtSequence,
    );
    expect(authorizedRecord.activeFromSequence).toEqual(0n);
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(authorizedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(authorizationEventHash),
    );
    await expect((async () =>
      (await simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )))()).rejects.toThrow(/not active/i);

    const substitutedActivationEvidence = labelToBytes32("evidence:application:activate:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      async (signature) => (await simulator.activateIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        issuerAuthorization.authorizationId,
        substitutedActivationEvidence,
      )),
      /issuer activation evidence must match the proposed application/i,
    );

    const activationEvidenceHash = proposalEvidenceHash;
    const activationSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        activationEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    const activationEventHash = (await simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activationSignature,
      issuerAuthorization.authorizationId,
      activationEvidenceHash,
    ));
    const activeRecord = (await simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    ));

    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(activeRecord.statusPolicyBindingCommitment)).toEqual(
      Buffer.from(issuerAuthorization.statusPolicyBindingCommitment),
    );
    expect(activeRecord.activeFromSequence).toBeGreaterThan(
      authorizedRecord.authorizedAtSequence,
    );
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(1n);
    expect(Buffer.from(activeRecord.lifecycleEventHash)).toEqual(
      Buffer.from(activationEventHash),
    );
    expect(async () =>
      (await simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )),
    ).not.toThrow();
  });

  it("archives proposed issuer applications and revokes authorized issuer applications before activation", async () => {
    const registry = createInitializedRegistryFixture(21);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const archivedProposal = createIssuerAuthorizationFixture("archivable");
    const revocableAuthorization = createIssuerAuthorizationFixture("revocable");
    const verifier = await registerIssuerEvidenceVerifier(registry);
    const archivedProof = await issuerProposalProof(registry, archivedProposal, verifier);

    const archivedProposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      archivedProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeIssuerAuthorization(
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
    ));
    const proposedRecord = (await simulator.getIssuerAuthorization(
      archivedProposal.authorizationId,
    ));
    const archiveEvidenceHash = labelToBytes32("evidence:archivable:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        archivedProposal.authorizationId,
        proposedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      archivedProposal.authorizationId,
      archiveEvidenceHash,
    ));
    expect(
      (await simulator.getIssuerAuthorization(archivedProposal.authorizationId)).status,
    ).toEqual(AuthorizationStatus.archived);

    const revocableProof = await issuerProposalProof(registry, revocableAuthorization, verifier);
    const revocableProposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      revocableProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeIssuerAuthorization(
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
    ));
    const revocableProposedRecord = (await simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    ));
    const authorizeEvidenceHash = revocableAuthorization.evidenceHash;
    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        revocableProposedRecord.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      revocableAuthorization.authorizationId,
      authorizeEvidenceHash,
    ));
    const authorizedRecord = (await simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    ));
    const revokeEvidenceHash = labelToBytes32("evidence:revocable:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      revocableAuthorization.authorizationId,
      revokeEvidenceHash,
    ));

    expect(
      (await simulator.getIssuerAuthorization(revocableAuthorization.authorizationId))
        .status,
    ).toEqual(AuthorizationStatus.revoked);
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("suspends, revokes, and archives issuer authorizations while preserving append-only scope state", async () => {
    const registry = createInitializedRegistryFixture(23);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("degree");
    await activateIssuerAuthorizationFixture(registry, issuerAuthorization);

    const createdRecord = (await simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    ));
    const suspendEvidenceHash = labelToBytes32("evidence:degree:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      issuerAuthorization.authorizationId,
      suspendEvidenceHash,
    ));

    const suspendedRecord = (await simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    ));
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(0n);
    await expect((async () =>
      (await simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )))()).rejects.toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:degree:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      issuerAuthorization.authorizationId,
      revokeEvidenceHash,
    ));

    const revokedRecord = (await simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    ));
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:degree:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      issuerAuthorization.authorizationId,
      archiveEvidenceHash,
    ));

    const archivedRecord = (await simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    ));
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect((await simulator.getLedger()).activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate issuer scope proposals, invalid transitions, tampered signatures, and missing queries", async () => {
    const registry = createInitializedRegistryFixture(29);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("license");
    const verifier = await registerIssuerEvidenceVerifier(registry);

    await expect((async () =>
      (await simulator.getIssuerAuthorization(labelToBytes32("issuer-auth:missing"))))()).rejects.toThrow(/not registered/i);
    await expect((async () =>
      (await simulator.getCurrentIssuerAuthorization(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      )))()).rejects.toThrow(/scope is not registered/i);

    const proof = await issuerProposalProof(registry, issuerAuthorization, verifier);
    const proposalPayloadHash = proof.payloadHash;
    const tamperedProposalSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposalPayloadHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      response: 0n,
    };

    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
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
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);

    const proposalAuthorizationId = labelToBytes32("issuer-auth:license:proposal");
    const proposalEvidenceHash = labelToBytes32("evidence:license:proposal");
    const proposalProof = await issuerProposalProof(
      registry,
      { ...issuerAuthorization, authorizationId: proposalAuthorizationId, evidenceHash: proposalEvidenceHash },
      verifier,
    );
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposalProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeIssuerAuthorization(
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
    ));

    const duplicateProof = await issuerProposalProof(registry, {
      ...issuerAuthorization,
      authorizationId: labelToBytes32("issuer-auth:license:proposal:duplicate"),
      evidenceHash: labelToBytes32("evidence:license:proposal:duplicate"),
    }, verifier);

    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          duplicateProof.payloadHash,
          (await simulator.getLedger()).governanceActionCount,
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
      )))()).rejects.toThrow(/live authorization/i);

    await expect((async () =>
      (await simulator.activateIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          ACTIVATE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            proposalAuthorizationId,
            (await simulator.getIssuerAuthorization(proposalAuthorizationId))
              .lifecycleEventHash,
            labelToBytes32("evidence:license:activate"),
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        proposalAuthorizationId,
        labelToBytes32("evidence:license:activate"),
      )))()).rejects.toThrow(/must be authorized/i);

    const activeIssuerAuthorization = createIssuerAuthorizationFixture("license-active");
    await activateIssuerAuthorizationFixture(registry, activeIssuerAuthorization);
    const activeDuplicateProof = await issuerProposalProof(registry, {
      ...activeIssuerAuthorization,
      authorizationId: labelToBytes32("issuer-auth:license-active:duplicate"),
      evidenceHash: labelToBytes32("evidence:license-active:duplicate"),
    }, verifier);

    await expect((async () =>
      (await simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          activeDuplicateProof.payloadHash,
          (await simulator.getLedger()).governanceActionCount,
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
      )))()).rejects.toThrow(/live authorization/i);

    await expect((async () =>
      (await simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          AUTHORIZE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            (await simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            )).lifecycleEventHash,
            labelToBytes32("evidence:license-active:authorize"),
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license-active:authorize"),
      )))()).rejects.toThrow(/must be proposed/i);

    const createdRecord = (await simulator.getIssuerAuthorization(
      activeIssuerAuthorization.authorizationId,
    ));
    const archiveEvidenceHash = labelToBytes32("evidence:license:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        activeIssuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      activeIssuerAuthorization.authorizationId,
      archiveEvidenceHash,
    ));

    await expect((async () =>
      (await simulator.revokeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          REVOKE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            (await simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            )).lifecycleEventHash,
            labelToBytes32("evidence:license:revoke"),
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license:revoke"),
      )))()).rejects.toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active verifier authorization with predicate and disclosure scoped lookups", async () => {
    const registry = createInitializedRegistryFixture(31);
    const {
      simulator,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("age-gate");
    const eventHash = await activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const state = (await simulator.getLedger());
    const recordById = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    const recordByScope = (await simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    ));

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
    expect(async () =>
      (await simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      )),
    ).not.toThrow();
    await expect((async () =>
      (await simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        labelToBytes32("pred-set:age-gate:different"),
        verifierAuthorization.disclosureLevelCommitment,
      )))()).rejects.toThrow(/scope is not registered/i);
  });

  it("keeps two full request resources for one verifier and partial request tuple distinct", async () => {
    const registry = createInitializedRegistryFixture(32);
    const first = createVerifierAuthorizationFixture("same-profile");
    const second = {
      ...first,
      authorizationId: labelToBytes32("verifier-auth:same-profile:other-purpose"),
      requestResourceId: labelToBytes32("request-resource:same-profile:other-purpose"),
      evidenceHash: labelToBytes32("evidence:same-profile:other-purpose"),
    };
    expect(Buffer.from(second.requestResourceId)).not.toEqual(Buffer.from(first.requestResourceId));
    await activateVerifierAuthorizationFixture(registry, first);
    await activateVerifierAuthorizationFixture(registry, second);
    expect((await registry.simulator.getLedger()).activeVerifierAuthorizationCount).toBe(2n);
    for (const authorization of [first, second]) {
      const current = await registry.simulator.getCurrentVerifierAuthorization(
        authorization.subjectDidCommitment,
        authorization.requestResourceId,
        authorization.allowedAttributeSetCommitment,
        authorization.allowedPredicateSetCommitment,
        authorization.disclosureLevelCommitment,
      );
      expect(Buffer.from(current.authorizationId)).toEqual(Buffer.from(authorization.authorizationId));
    }
  });

  it("moves a verifier authorization through proposed, authorized, and active states", async () => {
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
    const proposalProof = await verifierProposalProof(registry, proposed);

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_VERIFIER_ACTION_KIND,
      proposalProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeVerifierAuthorization(
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
    ));

    const proposedRecord = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect((await simulator.getLedger()).activeVerifierAuthorizationCount).toEqual(0n);

    const substitutedAuthorizationEvidence = labelToBytes32("evidence:employment:authorize:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        substitutedAuthorizationEvidence,
      ),
      async (signature) => (await simulator.authorizeVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        verifierAuthorization.authorizationId,
        substitutedAuthorizationEvidence,
      )),
      /verifier authorization evidence must match the proposed application/i,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.authorizeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    ));

    const authorizedRecord = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect((await simulator.getLedger()).activeVerifierAuthorizationCount).toEqual(0n);

    const substitutedActivationEvidence = labelToBytes32("evidence:employment:activate:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      async (signature) => (await simulator.activateVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        verifierAuthorization.authorizationId,
        substitutedActivationEvidence,
      )),
      /verifier activation evidence must match the proposed application/i,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.activateVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    ));

    const activeRecord = (await simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    ));
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect((await simulator.getLedger()).activeVerifierAuthorizationCount).toEqual(1n);
  });

  it("suspends, revokes, and archives verifier authorizations while preserving scope-sensitive state", async () => {
    const registry = createInitializedRegistryFixture(37);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("university");
    await activateVerifierAuthorizationFixture(registry, verifierAuthorization);

    const createdRecord = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    const suspendEvidenceHash = labelToBytes32("evidence:university:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.suspendVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      verifierAuthorization.authorizationId,
      suspendEvidenceHash,
    ));

    const suspendedRecord = (await simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    ));
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect((await simulator.getLedger()).activeVerifierAuthorizationCount).toEqual(0n);
    await expect((async () =>
      (await simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      )))()).rejects.toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:university:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.revokeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      verifierAuthorization.authorizationId,
      revokeEvidenceHash,
    ));

    const revokedRecord = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:university:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    ));

    const archivedRecord = (await simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestResourceId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    ));
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect((await simulator.getLedger()).activeVerifierAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate verifier scopes, invalid transitions, tampered signatures, and missing verifier queries", async () => {
    const registry = createInitializedRegistryFixture(41);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("passport");

    await expect((async () =>
      (await simulator.getVerifierAuthorization(labelToBytes32("verifier-auth:missing"))))()).rejects.toThrow(/not registered/i);
    await expect((async () =>
      (await simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      )))()).rejects.toThrow(/scope is not registered/i);

    const proposalProof = await verifierProposalProof(registry, verifierAuthorization);
    const tamperedProposeSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        proposalProof.payloadHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      response: 0n,
    };
    await expect((async () => (await simulator.proposeVerifierAuthorization(
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
    )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);

    await activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const duplicate = {
      ...verifierAuthorization,
      authorizationId: labelToBytes32("verifier-auth:passport:duplicate"),
      evidenceHash: labelToBytes32("evidence:passport:duplicate"),
    };
    const duplicateProof = await verifierProposalProof(registry, duplicate);
    await expect((async () => (await simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        duplicateProof.payloadHash,
        (await simulator.getLedger()).governanceActionCount,
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
    )))()).rejects.toThrow(/live authorization/i);
    const createdRecord = (await simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    ));
    const archiveEvidenceHash = labelToBytes32("evidence:passport:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    ));

    await expect((async () =>
      (await simulator.revokeVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          REVOKE_VERIFIER_ACTION_KIND,
          computeUpdateVerifierAuthorizationPayloadHash(
            verifierAuthorization.authorizationId,
            (await simulator.getVerifierAuthorization(verifierAuthorization.authorizationId))
              .lifecycleEventHash,
            labelToBytes32("evidence:passport:revoke"),
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        verifierAuthorization.authorizationId,
        labelToBytes32("evidence:passport:revoke"),
      )))()).rejects.toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active recognition by id and scope", async () => {
    const registry = createInitializedRegistryFixture(43);
    const {
      simulator,
    } = registry;
    const recognition = createRecognitionFixture("gaia-x");
    const eventHash = await activateRecognitionFixture(registry, recognition);
    const state = (await simulator.getLedger());
    const recordById = (await simulator.getRecognition(recognition.recognitionId));
    const recordByScope = (await simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    ));

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
    expect(async () =>
      (await simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      )),
    ).not.toThrow();
  });

  it("binds recognition proposal evidence to its scope and an active verifier key", async () => {
    const registry = createInitializedRegistryFixture(44);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const recognition = createRecognitionFixture("recognition-proof");
    const proof = await recognitionProposalProof(registry, recognition, recognition.evidenceHash);
    const sign = async (kind: Uint8Array, payloadHash: Uint8Array) =>
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        kind, payloadHash, (await simulator.getLedger()).governanceActionCount,
      );
    const propose = async (
      payloadHash: Uint8Array,
      evidenceSignature: typeof proof.evidenceSignature,
      recognizedRegistryId = recognition.recognizedRegistryId,
    ) => (await simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      await sign(PROPOSE_RECOGNITION_ACTION_KIND, payloadHash),
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
    ));

    await expect(propose(proof.payloadHash, {
      ...proof.evidenceSignature,
      response: 0n,
    })).rejects.toThrow(/invalid jubjub schnorr signature/i);
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
      (await simulator.getLedger()).governancePolicyCommitment,
      (await simulator.getLedger()).governancePolicyVersion,
    );
    await expect(propose(
      substitutedPayload, proof.evidenceSignature, substitutedRegistryId,
    )).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).recognitionCount).toEqual(0n);

    const eventHash = await propose(proof.payloadHash, proof.evidenceSignature);
    const stored = (await simulator.getRecognitionProposalEvidence(recognition.recognitionId));
    expect(Buffer.from(stored.evidenceVerifierAuthorizationId)).toEqual(
      Buffer.from(proof.verifierAuthorizationId),
    );
    expect(Buffer.from(stored.evidenceCommitment)).toEqual(Buffer.from(recognition.evidenceHash));
    expect(Buffer.from(stored.proposalGovernanceEventHash)).toEqual(Buffer.from(eventHash));
    expect(stored.verifierSignatureResponse).toEqual(proof.evidenceSignature.response);

    const suspensionReason = labelToBytes32("reason:recognition-verifier-suspend");
    (await simulator.suspendEvidenceVerifierKey(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      await sign(SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
        computeUpdateEvidenceVerifierKeyPayloadHash(
          proof.verifierAuthorizationId,
          (await simulator.getEvidenceVerifierKey(proof.verifierAuthorizationId)).lifecycleEventHash,
          suspensionReason,
        )),
      proof.verifierAuthorizationId,
      suspensionReason,
    ));
    await expect((async () => (await simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      await sign(AUTHORIZE_RECOGNITION_ACTION_KIND,
        computeUpdateRecognitionPayloadHash(
          recognition.recognitionId,
          eventHash,
          recognition.evidenceHash,
        )),
      recognition.recognitionId,
      recognition.evidenceHash,
    )))()).rejects.toThrow(/evidence verifier key is not active/i);
    expect((await simulator.getRecognition(recognition.recognitionId)).status).toEqual(
      AuthorizationStatus.proposed,
    );
  });

  it("moves a recognition through proposed, authorized, and active states", async () => {
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
    const proof = await recognitionProposalProof(registry, recognition, proposedEvidenceHash);

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_RECOGNITION_ACTION_KIND,
      proof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeRecognition(
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
    ));

    const proposedRecord = (await simulator.getRecognition(recognition.recognitionId));
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect((await simulator.getLedger()).activeRecognitionCount).toEqual(0n);

    const replacementAuthorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () => (await simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementAuthorizeSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )))()).rejects.toThrow(/evidence must match the proposed application/i);
    expect((await simulator.getRecognition(recognition.recognitionId)).status).toEqual(
      AuthorizationStatus.proposed,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    ));

    const authorizedRecord = (await simulator.getRecognition(recognition.recognitionId));
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect((await simulator.getLedger()).activeRecognitionCount).toEqual(0n);

    const replacementActivateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () => (await simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementActivateSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )))()).rejects.toThrow(/activation evidence must match the proposed application/i);
    expect((await simulator.getRecognition(recognition.recognitionId)).status).toEqual(
      AuthorizationStatus.authorized,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    ));

    const activeRecord = (await simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    ));
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect((await simulator.getLedger()).activeRecognitionCount).toEqual(1n);
  });

  it("suspends, revokes, and archives recognition records while preserving append-only scope state", async () => {
    const registry = createInitializedRegistryFixture(47);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("eidas");
    await activateRecognitionFixture(registry, recognition);

    const createdRecord = (await simulator.getRecognition(recognition.recognitionId));
    const suspendEvidenceHash = labelToBytes32("evidence:eidas:suspend");
    const suspendSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      SUSPEND_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.suspendRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      recognition.recognitionId,
      suspendEvidenceHash,
    ));

    const suspendedRecord = (await simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    ));
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect((await simulator.getLedger()).activeRecognitionCount).toEqual(0n);
    await expect((async () =>
      (await simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      )))()).rejects.toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:eidas:revoke");
    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.revokeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      recognition.recognitionId,
      revokeEvidenceHash,
    ));

    const revokedRecord = (await simulator.getRecognition(recognition.recognitionId));
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:eidas:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    ));

    const archivedRecord = (await simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    ));
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect((await simulator.getLedger()).activeRecognitionCount).toEqual(0n);
  });

  it("rejects duplicate recognition scopes, invalid transitions, tampered signatures, and missing recognition queries", async () => {
    const registry = createInitializedRegistryFixture(53);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("gaia-net");
    const proof = await recognitionProposalProof(registry, recognition, recognition.evidenceHash);

    await expect((async () =>
      (await simulator.getRecognition(labelToBytes32("recognition:missing"))))()).rejects.toThrow(/not registered/i);
    await expect((async () =>
      (await simulator.getCurrentRecognition(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      )))()).rejects.toThrow(/scope is not registered/i);

    const proposePayloadHash = proof.payloadHash;
    const tamperedProposeSignature = {
      ...signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        proposePayloadHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      response: 0n,
    };
    await expect((async () => (await simulator.proposeRecognition(
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
    )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);

    await activateRecognitionFixture(registry, recognition);
    const duplicate = {
      ...recognition,
      recognitionId: labelToBytes32("recognition:gaia-net:duplicate"),
      evidenceHash: labelToBytes32("evidence:gaia-net:duplicate"),
    };
    const duplicateProof = await recognitionProposalProof(registry, duplicate, duplicate.evidenceHash);
    await expect((async () => (await simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed,
        registryId,
        (await simulator.getLedger()).governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        duplicateProof.payloadHash,
        (await simulator.getLedger()).governanceActionCount,
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
    )))()).rejects.toThrow(/live recognition/i);
    const createdRecord = (await simulator.getRecognition(recognition.recognitionId));
    const archiveEvidenceHash = labelToBytes32("evidence:gaia-net:archive");
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    ));

    await expect((async () =>
      (await simulator.revokeRecognition(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          REVOKE_RECOGNITION_ACTION_KIND,
          computeUpdateRecognitionPayloadHash(
            recognition.recognitionId,
            (await simulator.getRecognition(recognition.recognitionId))
              .lifecycleEventHash,
            labelToBytes32("evidence:gaia-net:revoke"),
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        recognition.recognitionId,
        labelToBytes32("evidence:gaia-net:revoke"),
      )))()).rejects.toThrow(/authorized, active, or suspended/i);
  });

  it("keeps two full request resources for one auditor and partial request tuple distinct", async () => {
    const registry = createInitializedRegistryFixture(56);
    const first = createAuditorAuthorizationFixture("same-profile");
    const second = {
      ...first,
      authorizationId: labelToBytes32("auditor-auth:same-profile:other-purpose"),
      requestResourceId: labelToBytes32("audit-request-resource:alt"),
      evidenceHash: labelToBytes32("evidence:audit-same-profile:other-purpose"),
    };
    expect(Buffer.from(second.requestResourceId)).not.toEqual(Buffer.from(first.requestResourceId));
    await activateAuditorAuthorizationFixture(registry, first);
    await activateAuditorAuthorizationFixture(registry, second);
    expect((await registry.simulator.getLedger()).activeAuditorAuthorizationCount).toBe(2n);
    for (const authorization of [first, second]) {
      const current = await registry.simulator.getCurrentAuditorAuthorization(
        authorization.subjectDidCommitment,
        authorization.requestResourceId,
        authorization.allowedAttributeSetCommitment,
        authorization.allowedPredicateSetCommitment,
        authorization.disclosureLevelCommitment,
      );
      expect(Buffer.from(current.authorizationId)).toEqual(Buffer.from(authorization.authorizationId));
    }
  });

  it("requires a registered evidence-verifier signature for auditor proposals", async () => {
    const registry = createInitializedRegistryFixture(60);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const auditor = createAuditorAuthorizationFixture("signed-mandate");
    const proof = await auditorProposalProof(registry, auditor);
    const sign = async () => signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash, (await simulator.getLedger()).governanceActionCount,
    );
    const propose = async (keyId: Uint8Array, evidenceSignature: typeof proof.evidenceSignature) =>
      (await simulator.proposeAuditorAuthorization(
        bootstrapMaintainer.keyId, bootstrapPublicKey, await sign(),
        auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
        auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
        auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel,
        auditor.evidenceHash, proof.verifierAuthorizationId, keyId, evidenceSignature,
      ));
    await expect((async () => (await simulator.getAuditorProposalEvidence(auditor.authorizationId)))()).rejects.toThrow(/not registered/i);
    await expect(propose(labelToBytes32("wrong-evidence-verifier-key"), proof.evidenceSignature))
      .rejects.toThrow(/key id does not match/i);
    await expect(propose(proof.verifierKeyIdCommitment,
      signVerifierProposalEvidenceFromSeed(
        new Uint8Array(32).fill(97), registryId, FIXTURE_NETWORK_ID_COMMITMENT,
        encodeContractAddress(simulator.contractAddress), proof.verifierKeyIdCommitment, proof.payloadHash,
      ))).rejects.toThrow(/invalid jubjub schnorr signature/i);
    expect((await simulator.getLedger()).auditorAuthorizationCount).toBe(0n);
    const eventHash = await propose(proof.verifierKeyIdCommitment, proof.evidenceSignature);
    const evidence = (await simulator.getAuditorProposalEvidence(auditor.authorizationId));
    expect(evidence.evidenceCommitment).toEqual(auditor.evidenceHash);
    expect(evidence.evidenceVerifierKeyIdCommitment).toEqual(proof.verifierKeyIdCommitment);
    expect(evidence.proposalGovernanceEventHash).toEqual(eventHash);
    await expect(propose(proof.verifierKeyIdCommitment, proof.evidenceSignature))
      .rejects.toThrow(/already exists/i);
  });

  it("rejects auditor approval after its proposal evidence policy is superseded", async () => {
    const registry = createInitializedRegistryFixture(61);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const auditor = createAuditorAuthorizationFixture("stale-mandate");
    const proof = await auditorProposalProof(registry, auditor);
    const proposalSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed, registryId, (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND, proof.payloadHash, (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeAuditorAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey, proposalSignature,
      auditor.authorizationId, auditor.subjectDidCommitment, auditor.requestResourceId,
      auditor.allowedAttributeSetCommitment, auditor.allowedPredicateSetCommitment,
      auditor.disclosureLevelCommitment, auditor.policyId, auditor.trustLevel,
      auditor.evidenceHash, proof.verifierAuthorizationId, proof.verifierKeyIdCommitment,
      proof.evidenceSignature,
    ));
    const proposalEvent = (await simulator.getAuditorProposalEvidence(auditor.authorizationId)).proposalGovernanceEventHash;
    const oldPolicy = (await simulator.getLedger()).governancePolicyCommitment;
    const newPolicy = labelToBytes32("policy:auditor:evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      oldPolicy, newPolicy, 2n, 1n, 1n, 1n,
    );
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, oldPolicy,
        UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, policyHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      newPolicy, 2n, 1n, 1n, 1n,
    ));
    const record = (await simulator.getAuditorAuthorization(auditor.authorizationId));
    const approvalHash = computeUpdateAuditorAuthorizationPayloadHash(
      auditor.authorizationId, record.lifecycleEventHash, auditor.evidenceHash,
    );
    await expect((async () => (await simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId, bootstrapPublicKey,
      signFixtureDeploymentBoundActionFromSeed(simulator,
        bootstrapMaintainer.seed, registryId, newPolicy, AUTHORIZE_AUDITOR_ACTION_KIND,
        approvalHash, (await simulator.getLedger()).governanceActionCount,
      ),
      auditor.authorizationId, auditor.evidenceHash,
    )))()).rejects.toThrow(/proposal evidence policy is not current/i);
    expect((await simulator.getAuditorAuthorization(auditor.authorizationId)).status).toBe(AuthorizationStatus.proposed);
    expect((await simulator.getAuditorProposalEvidence(auditor.authorizationId)).proposalGovernanceEventHash)
      .toEqual(proposalEvent);
  });

  it("creates and governs auditor authorizations across proposal, activation, and archival paths", async () => {
    const registry = createInitializedRegistryFixture(57);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const auditorAuthorization = createAuditorAuthorizationFixture("iso-27001");
    const proposalEvidenceHash = labelToBytes32("evidence:iso-27001:propose");
    const proposalProof = await auditorProposalProof(registry,
      { ...auditorAuthorization, evidenceHash: proposalEvidenceHash });

    const proposeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND,
      proposalProof.payloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.proposeAuditorAuthorization(
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
    ));

    const proposedRecord = (await simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    ));
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);

    const substitutedAuthorizationEvidence = labelToBytes32("evidence:iso-27001:authorize:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        substitutedAuthorizationEvidence,
      ),
      async (signature) => (await simulator.authorizeAuditorAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        auditorAuthorization.authorizationId,
        substitutedAuthorizationEvidence,
      )),
      /auditor authorization evidence must match the proposed application/i,
    );

    const authorizeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposedRecord.evidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      auditorAuthorization.authorizationId,
      proposedRecord.evidenceHash,
    ));

    const authorizedRecord = (await simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    ));
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);

    const substitutedActivationEvidence = labelToBytes32("evidence:iso-27001:activate:substituted");
    await expectSignedEvidenceMismatch(
      registry,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        substitutedActivationEvidence,
      ),
      async (signature) => (await simulator.activateAuditorAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signature,
        auditorAuthorization.authorizationId,
        substitutedActivationEvidence,
      )),
      /auditor activation evidence must match the proposed application/i,
    );

    const activateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        authorizedRecord.evidenceHash,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.activateAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      auditorAuthorization.authorizationId,
      authorizedRecord.evidenceHash,
    ));

    const activeRecord = (await simulator.getCurrentAuditorAuthorization(
      auditorAuthorization.subjectDidCommitment,
      auditorAuthorization.requestResourceId,
      auditorAuthorization.allowedAttributeSetCommitment,
      auditorAuthorization.allowedPredicateSetCommitment,
      auditorAuthorization.disclosureLevelCommitment,
    ));
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect((await simulator.getLedger()).activeAuditorAuthorizationCount).toEqual(1n);
    expect(async () =>
      (await simulator.assertAuditorAuthorized(
        auditorAuthorization.subjectDidCommitment,
        auditorAuthorization.requestResourceId,
        auditorAuthorization.allowedAttributeSetCommitment,
        auditorAuthorization.allowedPredicateSetCommitment,
        auditorAuthorization.disclosureLevelCommitment,
      )),
    ).not.toThrow();

    const revokeSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      REVOKE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        activeRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:revoke"),
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.revokeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:revoke"),
    ));
    expect((await simulator.getLedger()).activeAuditorAuthorizationCount).toEqual(0n);

    const revokedRecord = (await simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    ));
    const archiveSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      ARCHIVE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:archive"),
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.archiveAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:archive"),
    ));
    expect(
      (await simulator.getAuditorAuthorization(auditorAuthorization.authorizationId)).status,
    ).toEqual(AuthorizationStatus.archived);
  });

  it("publishes and queries an epoch commitment by id and latest pointer", async () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(59);
    const epoch = createEpochCommitmentFixture(
      "seq-1",
      (await simulator.getLedger()).governancePolicyCommitment,
    );
    const actionSequence = (await simulator.getLedger()).governanceActionCount;
    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
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

    const eventHash = (await simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    ));
    const state = (await simulator.getLedger());
    const recordById = (await simulator.getEpochCommitment(epoch.epochId));
    const recordByLatest = (await simulator.getCurrentEpochCommitment());

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

  it("rejects missing epoch queries, invalid epoch windows, tampered signatures, and duplicate epoch ids", async () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(61);
    const epoch = createEpochCommitmentFixture(
      "seq-2",
      (await simulator.getLedger()).governancePolicyCommitment,
    );

    await expect((async () => (await simulator.getCurrentEpochCommitment()))()).rejects.toThrow(/no epoch commitment/i);
    await expect((async () =>
      (await simulator.getEpochCommitment(labelToBytes32("epoch:missing"))))()).rejects.toThrow(/not registered/i);

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
        (await simulator.getLedger()).governancePolicyCommitment,
        CREATE_EPOCH_ACTION_KIND,
        createPayloadHash,
        (await simulator.getLedger()).governanceActionCount,
      ),
      response: 0n,
    };

    await expect((async () =>
      (await simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      )))()).rejects.toThrow(/invalid jubjub schnorr signature/i);

    const uncommittedPolicyRoot = labelToBytes32("policy-root:uncommitted");
    const uncommittedSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () =>
      (await simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        uncommittedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      )))()).rejects.toThrow(/committed governance policy/i);

    const futureFrom = (await simulator.getLedger()).governanceActionCount + 1n;
    const futureSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    await expect((async () =>
      (await simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        futureSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      )))()).rejects.toThrow(/cannot start after its publication action/i);

    const signature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      createPayloadHash,
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    ));

    await expect((async () =>
      (await simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signFixtureDeploymentBoundActionFromSeed(simulator,
          bootstrapMaintainer.seed,
          registryId,
          (await simulator.getLedger()).governancePolicyCommitment,
          CREATE_EPOCH_ACTION_KIND,
          computeCreateEpochCommitmentPayloadHash(
            epoch.epochId,
            labelToBytes32("state-root:duplicate"),
            epoch.eventRoot,
            epoch.policyRoot,
            epoch.validFromSequence,
            epoch.validUntilSequence,
          ),
          (await simulator.getLedger()).governanceActionCount,
        ),
        epoch.epochId,
        labelToBytes32("state-root:duplicate"),
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      )))()).rejects.toThrow(/already exists/i);

    const revisionSequence = (await simulator.getLedger()).governanceActionCount;
    const revisedPolicyRoot = labelToBytes32("policy:midnight:v2");
    const revisionSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
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
    (await simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revisionSignature,
      revisedPolicyRoot,
      2n,
      1n,
      1n,
      1n,
    ));
    expect(Buffer.from((await simulator.getLedger()).lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(epoch.policyRoot),
    );
    const revisionEventHash = (await simulator.getLedger()).lastGovernanceEventHash;
    expect(Buffer.from(revisionEventHash)).toEqual(Buffer.from(pureCircuits.governanceEventHash(
      registryId,
      FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(simulator.contractAddress),
      epoch.policyRoot,
      (await simulator.getLedger()).lastAuthorizedSignerSetHash,
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
      (await simulator.getLedger()).governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        historicalEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        historicalFrom,
        historicalUntil,
      ),
      (await simulator.getLedger()).governanceActionCount,
    );
    (await simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      historicalSignature,
      historicalEpochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      historicalFrom,
      historicalUntil,
    ));
    const historicalRecord = (await simulator.getEpochCommitment(historicalEpochId));
    expect(Buffer.from(historicalRecord.policyRoot)).toEqual(Buffer.from(epoch.policyRoot));
    expect(Buffer.from(historicalRecord.publicationPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect(Buffer.from((await simulator.getLedger()).lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect((await simulator.getLedger()).governanceEventHashes.member(revisionEventHash)).toBe(true);

    const lateSequence = (await simulator.getLedger()).governanceActionCount;
    const lateEpochId = labelToBytes32("epoch:late-old-policy");
    const lateSignature = signFixtureDeploymentBoundActionFromSeed(simulator,
      bootstrapMaintainer.seed,
      registryId,
      (await simulator.getLedger()).governancePolicyCommitment,
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
    await expect((async () =>
      (await simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        lateSignature,
        lateEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        lateSequence,
        lateSequence + 60n,
      )))()).rejects.toThrow(/superseded at this sequence/i);
  });
});
