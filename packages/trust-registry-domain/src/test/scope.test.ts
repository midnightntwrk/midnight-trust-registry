import { describe, expect, it } from "vitest";

import {
  canonicalizeAuthorizationScope,
  computeAuthorizationScopeCommitment,
  encodeAuthorizationScope,
  issuerGovernedResourceId,
  issuerGovernedResourceIdFromScopeCommitment,
  requestGovernedResourceId,
  requestGovernedResourceIdFromScopeCommitment,
} from "../scope.js";
import { sha256Hex } from "../ids.js";
import { governedResourceInScope } from "../application-challenge-binding.js";

const issuer = {
  version: "tr-scope-v1" as const,
  role: "issuer" as const,
  credentialFamilyId: "https://schemas.midnight.network/credentials/organization",
  schemaId: "https://schemas.midnight.network/organization/v1",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "did:midnight:credential-definition:organization-v1",
  statusMethod: "midnight-status-registry-v1",
};

const request = {
  version: "tr-scope-v1" as const,
  role: "verifier" as const,
  requestProfileId: "https://profiles.midnight.network/admissions/v1",
  purpose: "university-admission",
  credentialScopeCommitment: "0x" + "1".repeat(64),
  allowedAttributes: ["issuer", "degree"],
  allowedPredicates: ["age_over_18"],
  disclosureLevel: "minimum",
};

describe("authorization scope v1", () => {
  it("produces a fixed UTF-8 vector for an issuer", () => {
    const canonical = canonicalizeAuthorizationScope(issuer);
    expect(canonical).toBe('{"credentialDefinitionId":"did:midnight:credential-definition:organization-v1","credentialFamilyId":"https://schemas.midnight.network/credentials/organization","role":"issuer","schemaId":"https://schemas.midnight.network/organization/v1","schemaVersion":"1.0.0","statusMethod":"midnight-status-registry-v1","version":"tr-scope-v1"}');
    expect(encodeAuthorizationScope(issuer)).toEqual(new TextEncoder().encode(canonical));
    expect(computeAuthorizationScopeCommitment(issuer)).toBe("0xf9d7d610bba907f28353425136f9ba2bc65d5925421371fc7580716029b3c6c8");
  });

  it("gives each issuer resource type a type-separated full-scope identity", () => {
    const familyId = issuerGovernedResourceId(issuer, "credentialFamily");
    expect(issuerGovernedResourceIdFromScopeCommitment(
      computeAuthorizationScopeCommitment(issuer), "credentialFamily",
    )).toBe(familyId);
    expect(familyId).toBe("tr:issuer-resource:v1:e4edbae272fdd78e6ceccde9e4018528ffa418094eeddae33782738293b3dd8d");
    expect(sha256Hex(familyId)).toBe("0xf4d2231e9d0bcb65bf7a39ab5b5893a4db0e199f209ee27ec1834344aee7162f");
    const types = [
      "credentialFamily", "schema", "schemaVersion", "credentialDefinition", "statusMethodRequirement",
    ] as const;
    const otherSchema = { ...issuer, schemaId: "https://schemas.midnight.network/organization/v2" };
    const otherFamily = { ...issuer, credentialFamilyId: "https://schemas.midnight.network/credentials/company" };
    const ids = types.map((type) => issuerGovernedResourceId(issuer, type));
    expect(new Set(ids).size).toBe(types.length);
    for (const type of types) {
      expect(issuerGovernedResourceId(otherSchema, type)).not.toBe(issuerGovernedResourceId(issuer, type));
      expect(issuerGovernedResourceId(otherFamily, type)).not.toBe(issuerGovernedResourceId(issuer, type));
    }
    expect(() => issuerGovernedResourceId(issuer, undefined as never)).toThrow();
    expect(() => issuerGovernedResourceId(issuer, "unknown" as never)).toThrow();
  });

  it("returns no governed resource for an invalid issuer scope", () => {
    expect(governedResourceInScope({ ...issuer, schemaVersion: "^1.0.0" }, "credentialFamily"))
      .toBeNull();
  });

  it("normalizes object fields and unordered request arrays", () => {
    const shuffled = { ...request, allowedAttributes: ["degree", "issuer"] };
    expect(canonicalizeAuthorizationScope(request)).toBe(canonicalizeAuthorizationScope(shuffled));
    expect(computeAuthorizationScopeCommitment(request)).toBe(computeAuthorizationScopeCommitment(shuffled));
    expect(computeAuthorizationScopeCommitment(request)).toBe("0x0c0cfd5d4aa1cb6f3207c4a2b4eea7a8728913173a386799e6a9cc274402b54d");
    expect(canonicalizeAuthorizationScope(request)).toContain('"allowedAttributes":["degree","issuer"]');
  });

  it("separates verifier, auditor, and maintainer roles", () => {
    const auditor = { ...request, role: "auditor" as const };
    const maintainer = { version: "tr-scope-v1" as const, role: "maintainer" as const, registryId: "tr:midnight:example" };
    expect(computeAuthorizationScopeCommitment(auditor)).toBe("0xdf9072c9d749045044d95c632ee9e1640686ab2e176d497144554cb79e8c23b1");
    expect(computeAuthorizationScopeCommitment(maintainer)).toBe("0x828e4df6eea28455dd5a993bcba67004f2520dfe17faab9cd94eb259180c94ad");
    expect(computeAuthorizationScopeCommitment(auditor)).not.toBe(computeAuthorizationScopeCommitment(request));
    expect(computeAuthorizationScopeCommitment(maintainer)).not.toBe(computeAuthorizationScopeCommitment(request));
  });

  it("gives the complete verifier and auditor request scope one canonical resource id", () => {
    const base = requestGovernedResourceId(request);
    expect(base).toBe("tr:request-resource:v1:f86e27170e169eae8c8e185911ea0b56b556e9da9c27bfcb202cb68e49fff6e5");
    expect(sha256Hex(base)).toBe("0xd960e89a62d3f51b12bcd906261dc3df026badb50f8650e7314746c2d2309823");
    expect(requestGovernedResourceIdFromScopeCommitment(
      computeAuthorizationScopeCommitment(request),
    )).toBe(base);
    expect(requestGovernedResourceId({ ...request, allowedAttributes: ["degree", "issuer"] })).toBe(base);
    expect(requestGovernedResourceId({ ...request, purpose: "research" })).not.toBe(base);
    expect(requestGovernedResourceId({ ...request, credentialScopeCommitment: `0x${"2".repeat(64)}` })).not.toBe(base);
    expect(requestGovernedResourceId({ ...request, allowedAttributes: ["degree"] })).not.toBe(base);
    expect(requestGovernedResourceId({ ...request, allowedPredicates: ["age_over_21"] })).not.toBe(base);
    expect(requestGovernedResourceId({ ...request, disclosureLevel: "full" })).not.toBe(base);
    expect(requestGovernedResourceId({ ...request, requestProfileId: "https://profiles.midnight.network/research/v1" })).not.toBe(base);
    const auditorId = requestGovernedResourceId({ ...request, role: "auditor" });
    expect(auditorId).toBe("tr:request-resource:v1:31c2d80f368b0e66c767a5cd86862e51048a2caddc2b423a6d2d2700d0c90a7e");
    expect(sha256Hex(auditorId)).toBe("0xeafc1934d592b84b1575c273bcb2f00c0cad015bd976da337fa984e2a35bf741");
    expect(auditorId).not.toBe(base);
    expect(() => requestGovernedResourceId({ ...request, allowedAttributes: ["degree", "degree"] })).toThrow();
    expect(() => requestGovernedResourceIdFromScopeCommitment(`0x${"A".repeat(64)}`)).toThrow();
  });

  it.each([
    [{ ...issuer, version: "tr-scope-v2" }, "unknown version"],
    [{ ...issuer, schemaVersion: "^1.0.0" }, "version range"],
    [{ ...issuer, schemaId: "https://schemas.midnight.network/*" }, "wildcard"],
    [{ ...issuer, extra: "ignored" }, "unknown field"],
    [{ ...issuer, credentialFamilyId: " leading-space" }, "ambiguous whitespace"],
    [{ ...request, allowedAttributes: ["degree", "degree"] }, "duplicate attribute"],
    [{ ...request, allowedPredicates: ["age_*" ] }, "wildcard predicate"],
    [{ ...request, credentialScopeCommitment: "0x" + "A".repeat(64) }, "noncanonical hex"],
    [{ ...issuer, statusMethod: "bad\ud800" }, "lone surrogate"],
    [{ ...issuer, statusMethod: "bad\u0085" }, "C1 control"],
    [{ ...issuer, statusMethod: "cafe\u0301" }, "non-NFC text"],
    [{ ...issuer, statusMethod: "issuer\u200bstatus" }, "invisible character"],
    [{ version: "tr-scope-v1", role: "maintainer", registryId: "TR:Midnight:Example" }, "mixed-case registry ID"],
  ].map(([input, reason]) => ({ input, reason })))("rejects $reason", ({ input }) => {
    expect(() => canonicalizeAuthorizationScope(input as typeof issuer)).toThrow();
  });
});
