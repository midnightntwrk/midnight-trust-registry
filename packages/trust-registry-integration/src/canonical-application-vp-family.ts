import { Buffer } from "node:buffer";

import { createMidnightDIDHolderBinding, resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString, type MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import type { TrustedDecisionEvidenceReaders } from "@midnightntwrk/trust-registry-client";
import {
  AuthorizationScopeSchema,
  HashHexSchema,
  IssuerScopeSchema,
  canonicalizeJson,
  computeAuthorizationScopeCommitment,
  issuerGovernedResourceId,
  sha256Hex,
  type AuthorizationScope,
  type DecisionEvidenceSelection,
  type IssuerStatusPolicyBinding,
} from "@midnightntwrk/trust-registry-domain";
import { z } from "zod";

import {
  ApplicationVpDependencyUnavailableError,
  type ApplicationVpFamilyAdapter,
  type ApplicationVpMaterial,
  type QualifiedApplicationVpFamilyAdapter,
} from "./application-vp-verifier.js";
import { decodeApplicationVpProof } from "./application-vp-proof-json.js";
import { createGovernedApplicationIssuerEligibility } from "./governed-application-issuer.js";

const MAX_BODY_BYTES = 16_384;
const Did = z.string().startsWith("did:midnight:");
const Method = z.string().min(1);
const Time = z.number().refine((value) => Number.isSafeInteger(value) && value >= 0);
const CredentialBody = z.strictObject({
  version: z.literal("tr-application-vp-credential-v1"),
  issuerDid: Did,
  issuerMethodId: Method,
  credentialSchemaId: IssuerScopeSchema.shape.schemaId,
  credentialIssuerScopeCommitment: HashHexSchema,
  subjectDid: Did,
  holderMethodId: Method,
  scope: AuthorizationScopeSchema,
  claimsCommitment: HashHexSchema,
  statusRegistryId: HashHexSchema,
  statusAuthorityMethod: Method,
  statusHandleCommitment: HashHexSchema,
  credentialExpiresAtMs: Time,
});
const PresentationBody = z.strictObject({
  version: z.literal("tr-application-vp-presentation-v1"),
  subjectDid: Did,
  credentialBodyRoot: HashHexSchema,
  origin: z.string().min(1),
  registryId: z.string().min(1),
  genesisHash: HashHexSchema,
  contractAddress: HashHexSchema,
  nonce: HashHexSchema,
  role: z.enum(["issuer", "verifier", "auditor", "maintainer"]),
  scopeCommitment: HashHexSchema,
  policyId: z.string().min(1),
  policyVersion: z.string().min(1),
});
const Submission = z.strictObject({
  rawCredentialBody: z.string().min(1),
  rawPresentationBody: z.string().min(1),
  credentialProof: z.unknown(),
  presentationProof: z.unknown(),
});

export type CanonicalApplicationVpSubmission = z.infer<typeof Submission>;
type Credential = z.infer<typeof CredentialBody>;
type Presentation = z.infer<typeof PresentationBody>;

function parseBody<T>(raw: string, schema: z.ZodType<T>): T {
  if (Buffer.byteLength(raw) > MAX_BODY_BYTES) throw new TypeError("Application VP body exceeds size limit");
  const parsed: unknown = JSON.parse(raw);
  const body = schema.parse(parsed);
  if (canonicalizeJson(body) !== raw) throw new TypeError("Application VP body is not canonical JSON");
  return body;
}

function root(raw: string): Uint8Array {
  return Buffer.from(sha256Hex(raw).slice(2), "hex");
}

function hex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

/** Binds schema-specific signed bodies to the published VC proofs; trust decisions remain host-owned. */
export function createCanonicalApplicationVpFamilyAdapter(input: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  /** Must be the schema ID in the host-selected active issuer grant. */
  expectedCredentialSchemaId: string;
  /** Must commit to the full host-selected issuer scope, not only its schema ID. */
  expectedIssuerScopeCommitment: string;
  issuerEligibility: ApplicationVpFamilyAdapter<CanonicalApplicationVpSubmission>["assertIssuerEligible"];
  statusSource: (request: {
    material: ApplicationVpMaterial;
    binding: IssuerStatusPolicyBinding;
    nonce: string;
    evaluatedAtMs: number;
  }) => Promise<{ validUntilMs: number; statusDecisionCommitment: string;
    privateStatusWitness?: import("./application-status-attestation.js").PrivateApplicationStatusWitness }>;
}): QualifiedApplicationVpFamilyAdapter<CanonicalApplicationVpSubmission> {
  const expectedSchemaId = IssuerScopeSchema.shape.schemaId.parse(input.expectedCredentialSchemaId);
  const expectedIssuerScopeCommitment = HashHexSchema.parse(input.expectedIssuerScopeCommitment);
  const preparedBodies = new WeakMap<ApplicationVpMaterial, { credential: Credential; presentation: Presentation }>();
  const resolver: Pick<MidnightDIDResolverInterface, "resolveResult"> = {
    resolveResult: async (did) => {
      try {
        return await input.resolver.resolveResult(did);
      } catch {
        throw new ApplicationVpDependencyUnavailableError();
      }
    },
  };
  const bodies = (material: ApplicationVpMaterial) => {
    const value = preparedBodies.get(material);
    if (!value) throw new TypeError("Application VP material was not prepared by this adapter");
    return value;
  };
  return {
    async prepare(value) {
      const submission = Submission.parse(value);
      const credential = parseBody(submission.rawCredentialBody, CredentialBody);
      const presentation = parseBody(submission.rawPresentationBody, PresentationBody);
      const statusAuthorityDid = credential.statusAuthorityMethod.split("#", 1)[0]!;
      const [holderMethod, statusMethod] = await Promise.all([
        resolveMidnightDIDMethodBinding({
          resolver, did: parseMidnightDIDString(credential.subjectDid),
          verificationMethodId: credential.holderMethodId, relationship: "authentication",
        }),
        resolveMidnightDIDMethodBinding({
          resolver, did: parseMidnightDIDString(statusAuthorityDid),
          verificationMethodId: credential.statusAuthorityMethod, relationship: "assertionMethod",
        }),
      ]);
      const holderBinding = createMidnightDIDHolderBinding(holderMethod).explicitBinding;
      const material: ApplicationVpMaterial = {
        issuerDid: credential.issuerDid,
        issuerMethodId: credential.issuerMethodId,
        subjectDid: credential.subjectDid,
        holderMethodId: credential.holderMethodId,
        credentialProof: decodeApplicationVpProof(submission.credentialProof),
        presentationProof: decodeApplicationVpProof(submission.presentationProof),
        credentialBodyRoot: root(submission.rawCredentialBody),
        presentationBodyRoot: root(submission.rawPresentationBody),
        credentialHolderBinding: holderBinding,
        presentationHolderBinding: holderBinding,
        statusBinding: {
          registryRef: {
            registryId: Buffer.from(credential.statusRegistryId.slice(2), "hex"),
            authorityVerificationMethodRef: statusMethod.verificationMethodRef,
          },
          statusHandleCommitment: Buffer.from(credential.statusHandleCommitment.slice(2), "hex"),
        },
        credentialExpiresAtMs: credential.credentialExpiresAtMs,
      };
      preparedBodies.set(material, { credential, presentation });
      return material;
    },
    async assertCredentialBodyBinding(material) {
      const { credential, presentation } = bodies(material);
      if (credential.issuerDid !== material.issuerDid
        || credential.issuerMethodId !== material.issuerMethodId
        || credential.credentialSchemaId !== expectedSchemaId
        || credential.credentialIssuerScopeCommitment !== expectedIssuerScopeCommitment
        || credential.subjectDid !== material.subjectDid
        || credential.holderMethodId !== material.holderMethodId
        || credential.credentialExpiresAtMs !== material.credentialExpiresAtMs
        || credential.statusRegistryId !== hex(material.statusBinding.registryRef.registryId)
        || credential.statusHandleCommitment !== hex(material.statusBinding.statusHandleCommitment)
        || presentation.subjectDid !== material.subjectDid
        || presentation.credentialBodyRoot !== hex(material.credentialBodyRoot)) {
        throw new TypeError("Application VP credential or presentation body binding failed");
      }
      return true;
    },
    async assertIssuerEligible(material, scope) {
      bodies(material);
      return input.issuerEligibility(material, scope);
    },
    async assertStatusActive(material, binding, context) {
      bodies(material);
      return input.statusSource({ material, binding, ...context });
    },
    async assertRoleClaims(material) {
      const { credential } = bodies(material);
      return {
        claimsCommitment: credential.claimsCommitment,
        scopeCommitment: computeAuthorizationScopeCommitment(credential.scope),
      };
    },
    async assertPresentationBinding(material, expected) {
      const { presentation } = bodies(material);
      if (presentation.subjectDid !== expected.subjectDid
        || presentation.origin !== expected.origin
        || presentation.registryId !== expected.registryId
        || presentation.genesisHash !== expected.genesisHash
        || presentation.contractAddress !== expected.contractAddress
        || presentation.nonce !== expected.nonce
        || presentation.role !== expected.role
        || presentation.scopeCommitment !== expected.scopeCommitment
        || presentation.policyId !== expected.policyId
        || presentation.policyVersion !== expected.policyVersion) {
        throw new TypeError("Application VP presentation context differs from the trusted request");
      }
      return true;
    },
  };
}

/** Composes a signed schema match with independently authenticated issuer and status decisions. */
export function createGovernedCanonicalApplicationVpFamilyAdapter(input: {
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  readers: TrustedDecisionEvidenceReaders;
  loadEvidence: () => Promise<unknown>;
  allowedApplicationRoles: readonly AuthorizationScope["role"][];
  statusSource: Parameters<typeof createCanonicalApplicationVpFamilyAdapter>[0]["statusSource"];
}): QualifiedApplicationVpFamilyAdapter<CanonicalApplicationVpSubmission> {
  const scope = IssuerScopeSchema.parse(input.selection.scope);
  if (input.selection.role !== "issuer" || input.selection.resourceType !== "schema"
    || input.selection.resourceId !== issuerGovernedResourceId(scope, "schema")) {
    throw new Error("Application VP issuer selection must pin the exact governed credential schema");
  }
  return createCanonicalApplicationVpFamilyAdapter({
    resolver: input.resolver,
    expectedCredentialSchemaId: scope.schemaId,
    expectedIssuerScopeCommitment: computeAuthorizationScopeCommitment(scope),
    issuerEligibility: createGovernedApplicationIssuerEligibility(input),
    statusSource: input.statusSource,
  });
}
