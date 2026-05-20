import { Buffer } from "node:buffer";

import {
  createMidnightDIDString,
  MidnightNetwork,
  parseContractAddress,
} from "@midnight-ntwrk/midnight-did";
import {
  createScopedIdentifier,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

export const bytes32Commitment = (value: string): Uint8Array =>
  Buffer.from(sha256Hex(value).slice(2), "hex");

export const createMidnightDid = (label: string): string =>
  createMidnightDIDString(
    parseContractAddress(sha256Hex(`midnight-did:${label}`).slice(2)),
    MidnightNetwork.Undeployed,
  );

export const createWebDid = (label: string): string =>
  `did:web:${label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, "-")
    .replace(/-+/g, "-")}.example`;

export type IssuerScenarioFixture = {
  authorizationId: string;
  authorizationIdCommitment: Uint8Array;
  subjectDid: string;
  subjectDidCommitment: Uint8Array;
  resourceType: IssuerResourceType;
  resourceId: string;
  resourceIdCommitment: Uint8Array;
  trustLevel: string;
  referencedStatusRegistryId: string;
};

export type VerifierScenarioFixture = {
  authorizationId: string;
  authorizationIdCommitment: Uint8Array;
  subjectDid: string;
  subjectDidCommitment: Uint8Array;
  requestProfileId: string;
  requestProfileIdCommitment: Uint8Array;
  allowedAttributeSetId: string;
  allowedAttributeSetCommitment: Uint8Array;
  allowedPredicateSetId: string;
  allowedPredicateSetCommitment: Uint8Array;
  disclosureLevelId: string;
  disclosureLevelCommitment: Uint8Array;
  scopeResourceId: string;
  trustLevel: string;
  referencedStatusRegistryId: string;
};

export type RecognitionScenarioFixture = {
  recognitionId: string;
  recognitionIdCommitment: Uint8Array;
  recognizedAuthorityDid: string;
  recognizedAuthorityDidCommitment: Uint8Array;
  recognizedRegistryId: string;
  recognizedRegistryIdCommitment: Uint8Array;
  scopeResourceType: string;
  scopeResourceTypeCommitment: Uint8Array;
  scopeResourceId: string;
  scopeResourceIdCommitment: Uint8Array;
  trustLevel: string;
};

export const createIssuerScenarioFixture = (
  label: string,
): IssuerScenarioFixture => {
  const authorizationId = createScopedIdentifier("auth", "issuer", label, "v1");
  const subjectDid = createMidnightDid(`issuer:${label}`);
  const resourceId = createScopedIdentifier("credential-family", label, "v1");

  return {
    authorizationId,
    authorizationIdCommitment: bytes32Commitment(authorizationId),
    subjectDid,
    subjectDidCommitment: bytes32Commitment(subjectDid),
    resourceType: IssuerResourceType.credentialFamily,
    resourceId,
    resourceIdCommitment: bytes32Commitment(resourceId),
    trustLevel: "approved",
    referencedStatusRegistryId: createScopedIdentifier(
      "status-registry",
      label,
      "v1",
    ),
  };
};

export const createRecognitionScenarioFixture = (
  label: string,
): RecognitionScenarioFixture => {
  const recognitionId = createScopedIdentifier("recognition", "authority", label, "v1");
  const recognizedAuthorityDid = createWebDid(`${label}.authority`);
  const recognizedRegistryId = createScopedIdentifier(
    "registry",
    "external",
    label,
    "v1",
  );
  const scopeResourceType = "recognized-scope";
  const scopeResourceId = createScopedIdentifier("credential-family", label, "v1");

  return {
    recognitionId,
    recognitionIdCommitment: bytes32Commitment(recognitionId),
    recognizedAuthorityDid,
    recognizedAuthorityDidCommitment: bytes32Commitment(recognizedAuthorityDid),
    recognizedRegistryId,
    recognizedRegistryIdCommitment: bytes32Commitment(recognizedRegistryId),
    scopeResourceType,
    scopeResourceTypeCommitment: bytes32Commitment(scopeResourceType),
    scopeResourceId,
    scopeResourceIdCommitment: bytes32Commitment(scopeResourceId),
    trustLevel: "peer-approved",
  };
};

export const createVerifierScenarioFixture = (
  label: string,
): VerifierScenarioFixture => {
  const authorizationId = createScopedIdentifier(
    "auth",
    "verifier",
    label,
    "v1",
  );
  const subjectDid = createMidnightDid(`verifier:${label}`);
  const requestProfileId = createScopedIdentifier("request-profile", label, "v1");
  const allowedAttributeSetId = createScopedIdentifier(
    "allowed-attribute-set",
    label,
    "minimal",
  );
  const allowedPredicateSetId = createScopedIdentifier(
    "allowed-predicate-set",
    label,
    "adult",
  );
  const disclosureLevelId = createScopedIdentifier(
    "disclosure-level",
    label,
    "selective",
  );
  const scopeResourceId = createScopedIdentifier(
    "request-profile-scope",
    label,
    "v1",
    "minimal",
    "adult",
    "selective",
  );

  return {
    authorizationId,
    authorizationIdCommitment: bytes32Commitment(authorizationId),
    subjectDid,
    subjectDidCommitment: bytes32Commitment(subjectDid),
    requestProfileId,
    requestProfileIdCommitment: bytes32Commitment(requestProfileId),
    allowedAttributeSetId,
    allowedAttributeSetCommitment: bytes32Commitment(allowedAttributeSetId),
    allowedPredicateSetId,
    allowedPredicateSetCommitment: bytes32Commitment(allowedPredicateSetId),
    disclosureLevelId,
    disclosureLevelCommitment: bytes32Commitment(disclosureLevelId),
    scopeResourceId,
    trustLevel: "approved",
    referencedStatusRegistryId: createScopedIdentifier(
      "status-registry",
      label,
      "v1",
    ),
  };
};
