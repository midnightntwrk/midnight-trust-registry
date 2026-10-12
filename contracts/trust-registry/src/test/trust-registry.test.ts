import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";

import {
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateEpochCommitmentPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeUpdateEvidenceVerifierKeyPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateAuditorAuthorizationPayloadHash,
  computeUpdateMaintainerMembershipPayloadHash,
  computeUpdateMaintainerThresholdPolicyPayloadHash,
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  computePolicyBoundActionPayloadHash,
  computePolicyBoundMaintainerActionDigest,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signPolicyBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  verifyPolicyBoundMaintainerAction,
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

it("encodes Compact action kinds exactly and rejects overlong values", () => {
  expect(encodeCompactActionKind("tr:epoch:publish")).toEqual(labelToBytes32("tr:epoch:publish"));
  expect(() => encodeCompactActionKind(`tr:${"x".repeat(30)}`)).toThrow(/exceeds Compact Bytes<32>/);
});

it("rejects malformed fixture labels before UTF-8 replacement can alias them", () => {
  expect(() => labelToBytes32(`${"x".repeat(31)}\ud800`)).toThrow(/valid UTF-16/);
  expect(() => labelToBytes32(`${"x".repeat(31)}\udc00`)).toThrow(/valid UTF-16/);
  expect(labelToBytes32("valid-\ud83d\ude00")).toHaveLength(32);
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
const UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND = encodeCompactActionKind(
  "tr:policy:thresholds:update",
);
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
    REGISTER_EVIDENCE_VERIFIER_ACTION_KIND, SUSPEND_EVIDENCE_VERIFIER_ACTION_KIND,
    REVOKE_EVIDENCE_VERIFIER_ACTION_KIND, ROTATE_EVIDENCE_VERIFIER_ACTION_KIND,
    UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND, CREATE_EPOCH_ACTION_KIND, GENERIC_AUDIT_ACTION_KIND,
  ];
  expect(new Set(compactKinds.map((kind) => Buffer.from(encodeCompactActionKind(kind)).toString("hex"))))
    .toEqual(new Set(expected.map((kind) => Buffer.from(kind).toString("hex"))));
});

const createInitializedRegistryFixture = (seedByte: number) => {
  const simulator = new TrustRegistrySimulator();
  const registryId = labelToBytes32("registry:kanon");
  const registryDidCommitment = labelToBytes32("did:midnight:registry");
  const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
  const bootstrapMaintainer = createMaintainerFixture("bootstrap", seedByte);
  const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
    bootstrapMaintainer.seed,
  );

  simulator.initializeRegistry(
    registryId,
    registryDidCommitment,
    governancePolicyCommitment,
    bootstrapMaintainer.maintainerId,
    bootstrapMaintainer.didCommitment,
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    1n,
  );

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
  if (existing) return existing;
  const verifier = {
    ...createMaintainerFixture("issuer-evidence-verifier", 97),
    authorizationId: labelToBytes32("evidence-verifier:issuer"),
    publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(97)),
  };
  const policyCommitment = simulator.getLedger().governancePolicyCommitment;
  const policyVersion = simulator.getLedger().governancePolicyVersion;
  const payloadHash = computeCreateEvidenceVerifierKeyPayloadHash(
    verifier.authorizationId, verifier.didCommitment, verifier.keyId, verifier.publicKey,
    labelToBytes32("jubjub-schnorr"), policyCommitment, policyVersion,
  );
  const sequence = simulator.getLedger().governanceActionCount;
  simulator.registerEvidenceVerifierKey(
    bootstrapMaintainer.keyId, bootstrapPublicKey,
    signPolicyBoundMaintainerActionFromSeed(
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
      verifier.seed, registryId, verifier.keyId, payloadHash,
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
    signPolicyBoundMaintainerActionFromSeed(
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
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
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
    sign(PROPOSE_VERIFIER_ACTION_KIND, computeCreateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      authorization.subjectDidCommitment,
      authorization.requestResourceId,
      authorization.allowedAttributeSetCommitment,
      authorization.allowedPredicateSetCommitment,
      authorization.disclosureLevelCommitment,
      authorization.policyId,
      authorization.trustLevel,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.requestResourceId,
    authorization.allowedAttributeSetCommitment,
    authorization.allowedPredicateSetCommitment,
    authorization.disclosureLevelCommitment,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
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
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
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
    sign(PROPOSE_RECOGNITION_ACTION_KIND, computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.recognizedAuthorityDidCommitment,
    recognition.recognizedRegistryId,
    recognition.scopeResourceType,
    recognition.scopeResourceId,
    recognition.policyId,
    recognition.trustLevel,
    recognition.evidenceHash,
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

const activateAuditorAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createAuditorAuthorizationFixture>,
): void => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
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
    sign(PROPOSE_AUDITOR_ACTION_KIND, computeCreateAuditorAuthorizationPayloadHash(
      authorization.authorizationId,
      authorization.subjectDidCommitment,
      authorization.requestResourceId,
      authorization.allowedAttributeSetCommitment,
      authorization.allowedPredicateSetCommitment,
      authorization.disclosureLevelCommitment,
      authorization.policyId,
      authorization.trustLevel,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.requestResourceId,
    authorization.allowedAttributeSetCommitment,
    authorization.allowedPredicateSetCommitment,
    authorization.disclosureLevelCommitment,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
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
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    registryId,
    simulator.getLedger().governancePolicyCommitment,
    actionKind,
    actionPayloadHash,
    actionSequence,
  ),
});

const expectSignedEvidenceMismatch = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  actionKind: Uint8Array,
  payloadHash: Uint8Array,
  invoke: (signature: ReturnType<typeof signPolicyBoundMaintainerActionFromSeed>) => void,
  diagnostic: RegExp,
): void => {
  const signature = signPolicyBoundMaintainerActionFromSeed(
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

  it("binds action payload hashes to a nonempty policy commitment", () => {
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const payload = labelToBytes32("action:payload");
    const bound = computePolicyBoundActionPayloadHash(policyV1, payload);

    expect(bound).toEqual(pureCircuits.policyBoundActionPayloadHash(policyV1, payload));
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(computePolicyBoundActionPayloadHash(policyV2, payload)).toString("hex"),
    );
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(computePolicyBoundActionPayloadHash(policyV1, labelToBytes32("other"))).toString("hex"),
    );
    expect(() => computePolicyBoundActionPayloadHash(new Uint8Array(32), payload)).toThrow(
      /policy commitment must be set/i,
    );
    expect(() => computePolicyBoundActionPayloadHash(policyV1, payload.subarray(1))).toThrow(
      /action payload hash must be 32 bytes/i,
    );
  });

  it("signs the four-field action digest under one explicit policy snapshot", () => {
    const maintainer = createMaintainerFixture("policy-bound", 19);
    const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
    const registryId = labelToBytes32("registry:policy-bound");
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const actionKind = encodeCompactActionKind("tr:issuer:propose");
    const payload = labelToBytes32("issuer:proposal:payload");
    const signature = signPolicyBoundMaintainerActionFromSeed(
      maintainer.seed,
      registryId,
      policyV1,
      actionKind,
      payload,
      3n,
    );

    expect(computePolicyBoundMaintainerActionDigest(
      registryId, policyV1, actionKind, payload, 3n,
    )).toHaveLength(4);
    expect(verifyPolicyBoundMaintainerAction(
      publicKey, registryId, policyV1, actionKind, payload, 3n, signature,
    )).toBe(true);
    expect(verifyPolicyBoundMaintainerAction(
      publicKey, registryId, policyV2, actionKind, payload, 3n, signature,
    )).toBe(false);
  });

  it("accepts valid threshold rules and rejects invalid ones", () => {
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 2n)).not.toThrow();
    expect(() =>
      pureCircuits.assertValidMaintainerThresholdPolicy(3n, 2n, 1n, 1n),
    ).not.toThrow();
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

  it("initializes the registry with a bootstrap maintainer and records the initial governance event", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 7);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

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
    expect(maintainer.status).toEqual(MaintainerStatus.active);
    expect(Buffer.from(maintainer.keyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects invalid initialization payloads and repeated initialization", () => {
    const simulator = new TrustRegistrySimulator();
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 9);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    expect(() =>
      simulator.initializeRegistry(
        new Uint8Array(32),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/Registry id must be set/);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        new Uint8Array(32),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/Governance policy commitment must be set/);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        0n,
      ),
    ).toThrow(/threshold must be at least 1/i);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        2n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        { x: 0n, y: 1n },
        1n,
      ),
    ).toThrow(/signer point must not be identity/i);

    expect(() => pureCircuits.createMaintainerMembershipPayloadHash(
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      { x: 0n, y: 1n },
      labelToBytes32("policy:maintainer"),
      labelToBytes32("trust:level"),
      labelToBytes32("evidence:hash"),
    )).toThrow(/signer point must not be identity/i);

    simulator.initializeRegistry(
      labelToBytes32("registry:kanon"),
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon:second"),
        labelToBytes32("did:midnight:registry:second"),
        labelToBytes32("policy:kanon:v2"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/already been initialized/i);
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

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        candidate.maintainerDidCommitment,
        candidate.keyId,
        candidate.publicKey,
        candidate.policyId,
        candidate.trustLevel,
        candidate.evidenceHash,
      ),
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
    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const suspendEvidenceHash = labelToBytes32("evidence:governed:suspend");
    const suspendActionSequence = simulator.getLedger().governanceActionCount;
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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

  it("rejects duplicate live maintainer identity enrollment and protects the last active maintainer from deactivation", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(13);
    const selfCandidate = createMaintainerMembershipFixture("self", 14);
    selfCandidate.maintainerDidCommitment = bootstrapMaintainer.didCommitment;

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        selfCandidate.maintainerId,
        selfCandidate.maintainerDidCommitment,
        selfCandidate.keyId,
        selfCandidate.publicKey,
        selfCandidate.policyId,
        selfCandidate.trustLevel,
        selfCandidate.evidenceHash,
      ),
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
      ),
    ).toThrow(/already has a live membership/i);

    const suspendEvidenceHash = labelToBytes32("evidence:bootstrap:suspend");
    const suspendActionSequence = simulator.getLedger().governanceActionCount;
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        bootstrapMaintainer.maintainerId,
        simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)
          .lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );

    expect(() =>
      simulator.suspendMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        suspendSignature,
        bootstrapMaintainer.maintainerId,
        suspendEvidenceHash,
      ),
    ).toThrow(/threshold policy/i);
  });

  it("records a signed generic audit event without a lifecycle transition", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 3);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionKind = GENERIC_AUDIT_ACTION_KIND;
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyPolicyBoundMaintainerAction(
        bootstrapPublicKey,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        actionKind,
        actionPayloadHash,
        actionSequence,
        signature,
      ),
    ).toBe(true);

    const lifecycleSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        secondMaintainer.maintainerDidCommitment,
        secondMaintainer.keyId,
        secondMaintainer.publicKey,
        secondMaintainer.policyId,
        secondMaintainer.trustLevel,
        secondMaintainer.evidenceHash,
      ),
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
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const activateMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const invalidThresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const invalidThresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        labelToBytes32("policy:kanon:v2"),
        2n,
        3n,
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
        3n,
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
    const thresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
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

    const issuer = createIssuerAuthorizationFixture("quorum");
    const proposedEvidenceHash = labelToBytes32("evidence:quorum:issuer:propose");
    const issuerProof = issuerProposalProof(
      registry, { ...issuer, evidenceHash: proposedEvidenceHash },
      registerIssuerEvidenceVerifier(registry, secondMaintainer),
    );
    const proposeIssuerPayloadHash = issuerProof.payloadHash;

    const singleSignerSequence = simulator.getLedger().governanceActionCount;
    const singleSignerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const proposeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const stalePolicySignature = signPolicyBoundMaintainerActionFromSeed(
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
    const authorizeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const activateIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const suspendIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
  });

  it("rejects duplicate maintainer signers in quorum execution", () => {
    const registry = createInitializedRegistryFixture(17);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const secondMaintainer = createMaintainerMembershipFixture("duplicate", 18);

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        secondMaintainer.maintainerDidCommitment,
        secondMaintainer.keyId,
        secondMaintainer.publicKey,
        secondMaintainer.policyId,
        secondMaintainer.trustLevel,
        secondMaintainer.evidenceHash,
      ),
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
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const activateMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const thresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const thresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
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
    const proposeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
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
      signature: signPolicyBoundMaintainerActionFromSeed(
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
    ).toThrow(/must not contain duplicates/i);
  });

  it("rejects maintainer actions before initialization and rejects tampered authorization", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const actionKind = GENERIC_AUDIT_ACTION_KIND;
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 5);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const signatureBeforeInit = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      labelToBytes32("policy:kanon:v1"),
      actionKind,
      actionPayloadHash,
      0n,
    );

    expect(() =>
      simulator.authorizeMaintainerAuditEvent(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signatureBeforeInit,
        actionPayloadHash,
      ),
    ).toThrow(/not initialized/i);

    simulator.initializeRegistry(
      registryId,
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionSequence = simulator.getLedger().governanceActionCount;
    const validSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const signature = signPolicyBoundMaintainerActionFromSeed(
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
      signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
    const proposalSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const mismatchedAuthorizationSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const authorizationSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const activationSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const archivedProposalSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revocableProposalSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
      ...signPolicyBoundMaintainerActionFromSeed(
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
    const proposalSignature = signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestResourceId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        proposalEvidenceHash,
      ),
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

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const proposePayloadHash = computeCreateVerifierAuthorizationPayloadHash(
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
    const tamperedProposeSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        proposePayloadHash,
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
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const duplicate = {
      ...verifierAuthorization,
      authorizationId: labelToBytes32("verifier-auth:passport:duplicate"),
      evidenceHash: labelToBytes32("evidence:passport:duplicate"),
    };
    expect(() => simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        computeCreateVerifierAuthorizationPayloadHash(
          duplicate.authorizationId,
          duplicate.subjectDidCommitment,
          duplicate.requestResourceId,
          duplicate.allowedAttributeSetCommitment,
          duplicate.allowedPredicateSetCommitment,
          duplicate.disclosureLevelCommitment,
          duplicate.policyId,
          duplicate.trustLevel,
          duplicate.evidenceHash,
        ),
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
    )).toThrow(/live authorization/i);
    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:passport:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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

  it("moves a recognition through proposed, authorized, and active states", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(45);
    const recognition = createRecognitionFixture("gaia-x-application");
    const proposedEvidenceHash = labelToBytes32("evidence:gaia-x-application:propose");
    const replacementEvidenceHash = labelToBytes32("evidence:gaia-x-application:replacement");

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        proposedEvidenceHash,
      ),
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
    );

    const proposedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const replacementAuthorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const replacementActivateSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const proposePayloadHash = computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );
    const tamperedProposeSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
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
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateRecognitionFixture(registry, recognition);
    const duplicate = {
      ...recognition,
      recognitionId: labelToBytes32("recognition:gaia-net:duplicate"),
      evidenceHash: labelToBytes32("evidence:gaia-net:duplicate"),
    };
    expect(() => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        computeCreateRecognitionPayloadHash(
          duplicate.recognitionId,
          duplicate.recognizedAuthorityDidCommitment,
          duplicate.recognizedRegistryId,
          duplicate.scopeResourceType,
          duplicate.scopeResourceId,
          duplicate.policyId,
          duplicate.trustLevel,
          duplicate.evidenceHash,
        ),
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
    )).toThrow(/live recognition/i);
    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const archiveEvidenceHash = labelToBytes32("evidence:gaia-net:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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

  it("creates and governs auditor authorizations across proposal, activation, and archival paths", () => {
    const registry = createInitializedRegistryFixture(57);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const auditorAuthorization = createAuditorAuthorizationFixture("iso-27001");

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND,
      computeCreateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        auditorAuthorization.subjectDidCommitment,
        auditorAuthorization.requestResourceId,
        auditorAuthorization.allowedAttributeSetCommitment,
        auditorAuthorization.allowedPredicateSetCommitment,
        auditorAuthorization.disclosureLevelCommitment,
        auditorAuthorization.policyId,
        auditorAuthorization.trustLevel,
        labelToBytes32("evidence:iso-27001:propose"),
      ),
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
      labelToBytes32("evidence:iso-27001:propose"),
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

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const signature = signPolicyBoundMaintainerActionFromSeed(
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
      ...signPolicyBoundMaintainerActionFromSeed(
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
    const uncommittedSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const futureSignature = signPolicyBoundMaintainerActionFromSeed(
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

    const signature = signPolicyBoundMaintainerActionFromSeed(
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
        signPolicyBoundMaintainerActionFromSeed(
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
    const revisionSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const historicalSignature = signPolicyBoundMaintainerActionFromSeed(
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
    const lateSignature = signPolicyBoundMaintainerActionFromSeed(
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
