import { z } from "zod";
import { decodeJubjubJwkCoordinate } from "@midnight-ntwrk/midnight-did-domain";

import { computeAuthorizationStatementLeafHash, computeMerkleRootFromProof } from "./evidence-bundle.js";
import { HashHexSchema, ScopedIdentifierSchema } from "./ids.js";
import { compareRfc3339Instants } from "./instant.js";
import { LifecycleStatusSchema } from "./lifecycle.js";
import { GovernancePolicySnapshotSchema, computeGovernancePolicySnapshotCommitment } from "./policy-snapshot.js";
import { IssuerGovernedResourceIdSchema, RequestGovernedResourceIdSchema } from "./scope.js";
import { IssuerStatusPolicyBindingSchema, computeIssuerStatusPolicyBindingCommitment } from "./status-policy.js";
import { AuthorizationRecordSchema, ResourceTypeSchema } from "./types.js";

const HashSchema = HashHexSchema.regex(/^0x[0-9a-f]{64}$/u);
const IdentifierSchema = ScopedIdentifierSchema.regex(/^[a-z0-9][a-z0-9:._-]*$/u);
const MidnightDidSchema = z.string().regex(/^did:midnight:[a-z0-9]+:[0-9a-f]{64}$/u);
const MethodIdSchema = z.string().regex(/^did:midnight:[a-z0-9]+:[0-9a-f]{64}#[A-Za-z0-9:._-]+$/u);
const TimestampSchema = z.string().datetime({ offset: true });
const SequenceSchema = z.string().regex(/^(0|[1-9][0-9]*)$/u).refine(
  (value) => BigInt(value) <= 18446744073709551615n,
  "Sequence exceeds uint64",
);
const PositiveSequenceSchema = SequenceSchema.refine(
  (value) => value !== "0",
  "Sequence must be positive",
);
const MAX_MERKLE_PATH_DEPTH = 256;
const MerklePathSchema = z.array(HashSchema).min(1).max(MAX_MERKLE_PATH_DEPTH);
const JubjubCoordinateSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u).refine((value) => {
  try {
    decodeJubjubJwkCoordinate(value);
    return true;
  } catch {
    return false;
  }
}, "Jubjub coordinate must be a canonical 32-byte field element");
const SignatureSchema = z.strictObject({
  keyId: MethodIdSchema,
  algorithm: z.literal("jubjub-schnorr"),
  signature: z.string().regex(/^0x[0-9a-f]{192}$/u),
});

const GrantFields = {
  ...AuthorizationRecordSchema.shape,
  registryId: IdentifierSchema,
  subjectDid: MidnightDidSchema,
  policyId: IdentifierSchema,
  lifecycleEventRoot: HashSchema,
  evidenceHash: HashSchema,
  status: LifecycleStatusSchema,
};

export const DecisionEvidenceGrantSchema = z.discriminatedUnion("role", [
  z.strictObject({
    ...GrantFields,
    role: z.literal("issuer"),
    resourceType: ResourceTypeSchema.extract([
      "credential-family", "schema", "schema-version", "credential-definition", "status-method-requirement",
    ]),
    resourceId: IssuerGovernedResourceIdSchema,
    statusPolicyBindingCommitment: HashSchema,
  }),
  z.strictObject({
    ...GrantFields,
    role: z.literal("verifier"),
    resourceType: z.literal("request-profile"),
    resourceId: RequestGovernedResourceIdSchema,
    statusPolicyBindingCommitment: z.never().optional(),
  }),
]);

const DidStateEvidenceSchema = z.discriminatedUnion("evidenceType", [
  z.strictObject({
    evidenceType: z.literal("ledger-observation"),
    blockHash: HashSchema,
    transactionHash: HashSchema,
  }),
  z.strictObject({
    evidenceType: z.literal("state-proof"),
    stateRoot: HashSchema,
    leafHash: HashSchema,
    path: MerklePathSchema,
    leafIndex: SequenceSchema,
    blockHash: HashSchema,
  }),
]);

const DidMethodSchema = z.strictObject({
  did: MidnightDidSchema,
  methodId: MethodIdSchema,
  methodType: z.literal("JsonWebKey"),
  controller: MidnightDidSchema,
  publicKeyJwk: z.strictObject({
    kty: z.literal("EC"),
    crv: z.literal("Jubjub"),
    x: JubjubCoordinateSchema,
    y: JubjubCoordinateSchema,
  }),
  stateVersion: PositiveSequenceSchema,
  stateEvidence: DidStateEvidenceSchema,
});

const IssuerDidMethodSchema = DidMethodSchema.safeExtend({ relationship: z.literal("assertionMethod") });
const VerifierDidMethodSchema = DidMethodSchema.safeExtend({
  relationship: z.enum(["authentication", "capabilityInvocation"]),
});

export const DecisionEvidenceEpochSchema = z.strictObject({
  epochId: IdentifierSchema,
  registryId: IdentifierSchema,
  stateRoot: HashSchema,
  eventRoot: HashSchema,
  policyRoot: HashSchema,
  publicationPolicyCommitment: HashSchema,
  publicationSequence: PositiveSequenceSchema,
  validFromSequence: SequenceSchema,
  validUntilSequence: PositiveSequenceSchema,
  validFrom: TimestampSchema,
  validUntil: TimestampSchema,
  quorum: z.strictObject({
    requiredSignatures: z.number().int().min(1).max(5),
    signatures: z.array(SignatureSchema).min(1).max(5),
  }),
});

const BaseEnvelope = {
  format: z.literal("tr-decision-evidence-v1"),
  registry: z.strictObject({
    registryId: IdentifierSchema,
    registryDid: MidnightDidSchema,
    networkId: IdentifierSchema,
    contractAddress: HashSchema,
  }),
  // These are lookup references only. The verifier must obtain accepted anchors independently.
  anchorReferences: z.strictObject({
    registryEpoch: z.strictObject({
      networkId: IdentifierSchema,
      contractAddress: HashSchema,
      transactionHash: HashSchema,
      blockHash: HashSchema,
    }),
    didState: z.strictObject({
      networkId: IdentifierSchema,
      blockHash: HashSchema,
    }),
  }),
  epoch: DecisionEvidenceEpochSchema,
  policy: GovernancePolicySnapshotSchema,
  inclusionProof: z.strictObject({
    proofType: z.literal("merkle-inclusion"),
    root: HashSchema,
    leafHash: HashSchema,
    path: MerklePathSchema,
    leafIndex: SequenceSchema,
  }),
  // Only epochPublication is verified below; other hashes are unverified lookup references.
  governanceEvents: z.strictObject({
    grantTransition: HashSchema,
    quorumApproval: HashSchema,
    epochPublication: HashSchema,
    policySnapshot: HashSchema,
    supersession: HashSchema.optional(),
  }),
  decisionSequence: PositiveSequenceSchema,
};

const DecisionEvidenceShape = z.discriminatedUnion("role", [
  z.strictObject({
    ...BaseEnvelope,
    role: z.literal("issuer"),
    grant: DecisionEvidenceGrantSchema.options[0],
    didMethod: IssuerDidMethodSchema,
    statusPolicyBinding: IssuerStatusPolicyBindingSchema,
  }),
  z.strictObject({
    ...BaseEnvelope,
    role: z.literal("verifier"),
    grant: DecisionEvidenceGrantSchema.options[1],
    didMethod: VerifierDidMethodSchema,
    statusPolicyBinding: z.never().optional(),
  }),
]);

export const DecisionEvidenceSchema = DecisionEvidenceShape.superRefine((evidence, ctx) => {
  if (BigInt(evidence.decisionSequence) < BigInt(evidence.epoch.publicationSequence)) {
    ctx.addIssue({ code: "custom", path: ["decisionSequence"], message: "Decision sequence predates epoch publication" });
  }
  if (BigInt(evidence.decisionSequence) > BigInt(evidence.epoch.validUntilSequence)) {
    ctx.addIssue({ code: "custom", path: ["decisionSequence"], message: "Decision sequence is outside the epoch window" });
  }
  if (compareRfc3339Instants(evidence.epoch.validFrom, evidence.epoch.validUntil) >= 0) {
    ctx.addIssue({ code: "custom", path: ["epoch", "validUntil"], message: "Epoch validity window must increase" });
  }
  if (
    BigInt(evidence.epoch.validFromSequence) > BigInt(evidence.epoch.publicationSequence)
    || BigInt(evidence.epoch.validUntilSequence) <= BigInt(evidence.epoch.validFromSequence)
  ) {
    ctx.addIssue({ code: "custom", path: ["epoch", "validUntilSequence"], message: "Epoch sequence window is invalid" });
  }
  const grant = AuthorizationRecordSchema.safeParse(evidence.grant);
  if (!grant.success) {
    for (const issue of grant.error.issues) {
      ctx.addIssue({ code: "custom", path: ["grant", ...issue.path], message: issue.message });
    }
  }
  if (evidence.epoch.quorum.signatures.length < evidence.epoch.quorum.requiredSignatures) {
    ctx.addIssue({ code: "custom", path: ["epoch", "quorum", "signatures"], message: "Signature set is smaller than the declared quorum" });
  }
  const keys = evidence.epoch.quorum.signatures.map((signature) => signature.keyId);
  if (new Set(keys).size !== keys.length) {
    ctx.addIssue({ code: "custom", path: ["epoch", "quorum", "signatures"], message: "Quorum signer keys must be distinct" });
  }
  if (evidence.grant.registryId !== evidence.registry.registryId || evidence.epoch.registryId !== evidence.registry.registryId || evidence.policy.registryId !== evidence.registry.registryId) {
    ctx.addIssue({ code: "custom", path: ["registry"], message: "Registry identifiers must agree" });
  }
  if (evidence.grant.subjectDid !== evidence.didMethod.did || evidence.didMethod.controller !== evidence.didMethod.did || !evidence.didMethod.methodId.startsWith(`${evidence.didMethod.did}#`)) {
    ctx.addIssue({ code: "custom", path: ["didMethod"], message: "DID method, controller, and grant subject must agree" });
  }
  if (evidence.anchorReferences.registryEpoch.networkId !== evidence.registry.networkId || evidence.anchorReferences.didState.networkId !== evidence.registry.networkId || evidence.anchorReferences.registryEpoch.contractAddress !== evidence.registry.contractAddress) {
    ctx.addIssue({ code: "custom", path: ["anchorReferences"], message: "Anchor lookup references must match the claimed registry network and contract" });
  }
  if (!evidence.registry.registryDid.startsWith(`did:midnight:${evidence.registry.networkId}:`) || !evidence.didMethod.did.startsWith(`did:midnight:${evidence.registry.networkId}:`)) {
    ctx.addIssue({ code: "custom", path: ["registry", "networkId"], message: "Registry and subject DIDs must use the claimed network" });
  }
  if (evidence.anchorReferences.didState.blockHash !== evidence.didMethod.stateEvidence.blockHash) {
    ctx.addIssue({ code: "custom", path: ["anchorReferences", "didState"], message: "DID state evidence must use the referenced block" });
  }
  if (evidence.inclusionProof.root !== evidence.epoch.stateRoot) {
    ctx.addIssue({ code: "custom", path: ["inclusionProof", "root"], message: "Inclusion root must match the claimed epoch state root" });
  }
  if (evidence.grant.status === "superseded" && evidence.governanceEvents.supersession === undefined) {
    ctx.addIssue({ code: "custom", path: ["governanceEvents", "supersession"], message: "Superseded grants require a supersession event reference" });
  }
  if (evidence.grant.policyId !== evidence.policy.policyId) {
    ctx.addIssue({ code: "custom", path: ["policy", "policyId"], message: "Grant and policy identifiers must agree" });
  }
  if (evidence.role === "issuer" && (
    evidence.statusPolicyBinding.trustRegistryId !== evidence.registry.registryId
    || evidence.statusPolicyBinding.issuerAuthorizationId !== evidence.grant.authorizationId
    || computeIssuerStatusPolicyBindingCommitment(evidence.statusPolicyBinding) !== evidence.grant.statusPolicyBindingCommitment
  )) {
    ctx.addIssue({ code: "custom", path: ["statusPolicyBinding"], message: "Issuer status policy binding does not match governed grant" });
  }
});

export const DecisionEvidenceJsonSchema = {
  ...z.toJSONSchema(DecisionEvidenceShape, { target: "draft-2020-12" }),
  $id: "https://midnight.network/schemas/trust-registry/decision-evidence-v1.json",
  title: "DecisionEvidence",
  description: "Structural claims only; parsing does not authenticate anchors, signatures, DID state, policy, or grant currency.",
};

export type DecisionEvidence = z.infer<typeof DecisionEvidenceSchema>;

export const AcceptedDecisionEpochSchema = z.strictObject({
  registryId: IdentifierSchema,
  registryDid: MidnightDidSchema,
  networkId: IdentifierSchema,
  contractAddress: HashSchema,
  transactionHash: HashSchema,
  blockHash: HashSchema,
  epochId: IdentifierSchema,
  stateRoot: HashSchema,
  eventRoot: HashSchema,
  policyRoot: HashSchema,
  publicationPolicyCommitment: HashSchema,
  publicationSequence: PositiveSequenceSchema,
  validFromSequence: SequenceSchema,
  validUntilSequence: PositiveSequenceSchema,
  publicationEventHash: HashSchema,
  validFrom: TimestampSchema,
  validUntil: TimestampSchema,
  requiredSignatures: z.number().int().min(1).max(5),
});

export type AcceptedDecisionEpoch = z.infer<typeof AcceptedDecisionEpochSchema>;

/** Compares against a caller-authenticated epoch; it does not authenticate that source or verify signatures. */
export const assertDecisionEvidenceMatchesAcceptedEpoch = (
  input: unknown,
  acceptedInput: unknown,
): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  const accepted = AcceptedDecisionEpochSchema.parse(acceptedInput);
  if (
    evidence.registry.registryId !== accepted.registryId
    || evidence.registry.registryDid !== accepted.registryDid
    || evidence.registry.networkId !== accepted.networkId
    || evidence.registry.contractAddress !== accepted.contractAddress
    || evidence.anchorReferences.registryEpoch.networkId !== accepted.networkId
    || evidence.anchorReferences.registryEpoch.contractAddress !== accepted.contractAddress
    || evidence.anchorReferences.registryEpoch.transactionHash !== accepted.transactionHash
    || evidence.anchorReferences.registryEpoch.blockHash !== accepted.blockHash
  ) {
    throw new Error("Decision evidence accepted epoch identity mismatch");
  }
  if (
    evidence.epoch.epochId !== accepted.epochId
    || evidence.epoch.registryId !== accepted.registryId
    || evidence.epoch.publicationSequence !== accepted.publicationSequence
    || evidence.epoch.validFromSequence !== accepted.validFromSequence
    || evidence.epoch.validUntilSequence !== accepted.validUntilSequence
    || evidence.governanceEvents.epochPublication !== accepted.publicationEventHash
  ) {
    throw new Error("Decision evidence accepted epoch publication mismatch");
  }
  if (
    evidence.epoch.stateRoot !== accepted.stateRoot
    || evidence.epoch.eventRoot !== accepted.eventRoot
    || evidence.epoch.policyRoot !== accepted.policyRoot
    || evidence.epoch.publicationPolicyCommitment !== accepted.publicationPolicyCommitment
  ) {
    throw new Error("Decision evidence accepted epoch root mismatch");
  }
  if (
    evidence.epoch.validFrom !== accepted.validFrom
    || evidence.epoch.validUntil !== accepted.validUntil
  ) {
    throw new Error("Decision evidence accepted epoch validity mismatch");
  }
  if (evidence.epoch.quorum.requiredSignatures !== accepted.requiredSignatures) {
    throw new Error("Decision evidence accepted epoch threshold mismatch");
  }
};

/** Checks the claimed grant path only; it does not authenticate the epoch root. */
export const assertDecisionEvidenceInclusion = (input: unknown): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  const proof = evidence.inclusionProof;
  const leafHash = computeAuthorizationStatementLeafHash(evidence.grant);
  if (proof.leafHash !== leafHash) {
    throw new Error("Decision evidence grant leaf hash mismatch");
  }
  const root = computeMerkleRootFromProof(leafHash, proof.path, BigInt(proof.leafIndex));
  if (root !== evidence.epoch.stateRoot) {
    throw new Error("Decision evidence Merkle root mismatch");
  }
};

/** Checks a claimed policy root; it does not authenticate the epoch or policy. */
export const assertDecisionEvidencePolicyCommitment = (input: unknown): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  if (computeGovernancePolicySnapshotCommitment(evidence.policy) !== evidence.epoch.policyRoot) {
    throw new Error("Decision evidence policy root mismatch");
  }
};

export type DecisionEvidenceSelection = {
  registryId: string;
  networkId: string;
  contractAddress: string;
  subjectDid: string;
  role: "issuer" | "verifier";
  resourceType: z.infer<typeof ResourceTypeSchema>;
  resourceId: string;
  evaluationTime: string;
};

/** Compares claimed evidence with caller-selected context; no anchor is authenticated here. */
export const assertDecisionEvidenceSelection = (
  input: unknown,
  expected: DecisionEvidenceSelection,
): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  assertDecisionEvidenceInclusion(evidence);
  assertDecisionEvidencePolicyCommitment(evidence);
  if (
    evidence.registry.registryId !== expected.registryId
    || evidence.registry.networkId !== expected.networkId
    || evidence.registry.contractAddress !== expected.contractAddress
    || evidence.grant.subjectDid !== expected.subjectDid
  ) {
    throw new Error("Decision evidence registry or subject mismatch");
  }
  if (
    evidence.role !== expected.role
    || evidence.grant.resourceType !== expected.resourceType
    || evidence.grant.resourceId !== expected.resourceId
  ) {
    throw new Error("Decision evidence role or resource scope mismatch");
  }
  if (
    evidence.grant.status !== "active"
    || evidence.grant.activeFrom === undefined
    || evidence.grant.suspendedAt !== undefined
    || evidence.grant.revokedAt !== undefined
    || evidence.grant.supersededAt !== undefined
    || evidence.grant.archivedAt !== undefined
  ) {
    throw new Error("Decision evidence grant is not active");
  }
  const at = TimestampSchema.parse(expected.evaluationTime);
  if (
    compareRfc3339Instants(at, evidence.epoch.validFrom) < 0
    || compareRfc3339Instants(at, evidence.epoch.validUntil) > 0
    || compareRfc3339Instants(at, evidence.policy.effectiveFrom) < 0
    || (evidence.policy.effectiveUntil !== null && compareRfc3339Instants(at, evidence.policy.effectiveUntil) >= 0)
    || compareRfc3339Instants(at, evidence.grant.activeFrom) < 0
    || (evidence.grant.effectiveUntil !== undefined && compareRfc3339Instants(at, evidence.grant.effectiveUntil) > 0)
  ) {
    throw new Error("Decision evidence is outside its claimed active window");
  }
};
