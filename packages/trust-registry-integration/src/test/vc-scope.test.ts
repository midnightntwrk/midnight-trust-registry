import { describe, expect, it } from "vitest";

import { pureCircuits } from "@midnight-ntwrk/credential-compact";
import { computeAuthorizationScopeCommitment } from "@midnight-ntwrk/trust-registry-domain";

import { createIssuerScenarioFixture, createVerifierAuthorizationScopeFixture, createVerifierScenarioFixture } from "../fixtures.js";
import { issuerSchemaRefFromRegistryScope, vcScopeCommitmentFromRegistryScope } from "../vc-scope.js";

describe("registry-to-VC scope mapping", () => {
  it("derives the exact VC issuer schema from the governed registry identifiers", () => {
    const scope = createIssuerScenarioFixture("vc-scope").authorizationScope;
    const schema = issuerSchemaRefFromRegistryScope(scope);
    expect(schema.majorVersion).toBe(1n);
    expect(schema.minorVersion).toBe(0n);
    expect(vcScopeCommitmentFromRegistryScope(scope)).toEqual(pureCircuits.issuerScopeCommitment(schema));
    expect(vcScopeCommitmentFromRegistryScope({ ...scope, schemaId: "other-schema" }))
      .not.toEqual(vcScopeCommitmentFromRegistryScope(scope));
    expect(vcScopeCommitmentFromRegistryScope({ ...scope, credentialFamilyId: "other-family" }))
      .not.toEqual(vcScopeCommitmentFromRegistryScope(scope));
    expect(vcScopeCommitmentFromRegistryScope({ ...scope, schemaVersion: "2.0.0" }))
      .not.toEqual(vcScopeCommitmentFromRegistryScope(scope));
  });

  it("fails closed when a registry version cannot be represented by VC SchemaRef", () => {
    const scope = createIssuerScenarioFixture("vc-version").authorizationScope;
    for (const schemaVersion of ["1.0.1", "0.1.0", "65536.0.0", "1.65536.0"]) {
      expect(() => issuerSchemaRefFromRegistryScope({ ...scope, schemaVersion })).toThrow(/not representable/u);
    }
  });

  it("binds verifier request proof scope to every governed request-profile field", () => {
    const scope = createVerifierAuthorizationScopeFixture(createVerifierScenarioFixture("vc-request"));
    expect(vcScopeCommitmentFromRegistryScope(scope)).toEqual(
      Uint8Array.from(Buffer.from(computeAuthorizationScopeCommitment(scope).slice(2), "hex")),
    );
    expect(vcScopeCommitmentFromRegistryScope({ ...scope, allowedPredicates: ["other-predicate"] }))
      .not.toEqual(vcScopeCommitmentFromRegistryScope(scope));
  });
});
