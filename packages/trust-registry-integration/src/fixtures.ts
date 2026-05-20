import { Buffer } from "node:buffer";

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
  `did:midnight:undeployed:${sha256Hex(`midnight-did:${label}`).slice(2)}`;

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
