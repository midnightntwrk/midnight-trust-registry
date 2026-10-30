import { Buffer } from "node:buffer";

import { pureCircuits, type SchemaRef } from "@midnight-ntwrk/credential-compact";
import {
  computeAuthorizationScopeCommitment,
  IssuerScopeSchema,
  sha256Hex,
  type AuthorizationScope,
} from "@midnight-ntwrk/trust-registry-domain";

const bytes32 = (hash: string): Uint8Array => Uint8Array.from(Buffer.from(hash.slice(2), "hex"));

/** A family or definition grant cannot be narrowed into schema signer authority. */
export const assertVcIssuerSchemaGrant = (resourceType: string): void => {
  if (resourceType !== "schema") {
    throw new Error("VC issuer signer authorization requires an exact schema grant");
  }
};

export const issuerSchemaRefFromRegistryScope = (
  scope: Extract<AuthorizationScope, { role: "issuer" }>,
): SchemaRef => {
  const parsedScope = IssuerScopeSchema.parse(scope);
  const [majorText, minorText, patchText] = parsedScope.schemaVersion.split(".");
  const majorVersion = Number(majorText);
  const minorVersion = Number(minorText);
  if (patchText !== "0" || !Number.isInteger(majorVersion) || majorVersion < 1 || majorVersion > 65535
    || !Number.isInteger(minorVersion) || minorVersion < 0 || minorVersion > 65535) {
    throw new Error("Registry schema version is not representable by VC SchemaRef");
  }
  return {
    packageId: bytes32(sha256Hex(`tr:vc-schema-package:v1:${parsedScope.credentialFamilyId}`)),
    schemaId: bytes32(sha256Hex(`tr:vc-schema-id:v1:${parsedScope.schemaId}`)),
    majorVersion: BigInt(majorVersion),
    minorVersion: BigInt(minorVersion),
  };
};

export const vcScopeCommitmentFromRegistryScope = (
  scope: Extract<AuthorizationScope, { role: "issuer" | "verifier" }>,
): Uint8Array => scope.role === "issuer"
  ? pureCircuits.issuerScopeCommitment(issuerSchemaRefFromRegistryScope(scope))
  : bytes32(computeAuthorizationScopeCommitment(scope));
