import { describe, expect, it } from "vitest";

import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "../did-resolution.js";
import {
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("trust registry DID integration", () => {
  it("resolves trusted issuer and verifier Midnight DIDs through the midnight-did resolver", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");
    const verifier = createVerifierScenarioFixture("employment");

    harness.authorizeIssuer(issuer);
    harness.authorizeVerifier(verifier);

    const issuerBundle = harness.evaluateCurrentIssuerDecision(issuer);
    const verifierBundle = harness.evaluateCurrentVerifierDecision(verifier);
    const issuerDidFixture = createMidnightDidLedgerFixture(
      issuerBundle.subjectDid,
      {
        serviceEndpoint: "https://issuer.example/did",
      },
    );
    const verifierDidFixture = createMidnightDidLedgerFixture(
      verifierBundle.subjectDid,
      {
        serviceEndpoint: "https://verifier.example/did",
      },
    );
    const resolver = createMidnightDidResolver([
      issuerDidFixture,
      verifierDidFixture,
    ]);

    const [issuerResolution, verifierResolution] = await Promise.all([
      resolver.resolveResult(issuerBundle.subjectDid),
      resolver.resolveResult(verifierBundle.subjectDid),
    ]);

    expect(issuerResolution?.didDocument.id).toBe(issuerBundle.subjectDid);
    expect(issuerResolution?.didDocument.authentication).toEqual(["#auth-1"]);
    expect(issuerResolution?.didDocument.service?.[0]?.serviceEndpoint).toBe(
      "https://issuer.example/did",
    );
    expect(issuerResolution?.didDocumentMetadata.versionId).toBe("1");

    expect(verifierResolution?.didDocument.id).toBe(verifierBundle.subjectDid);
    expect(verifierResolution?.didDocument.authentication).toEqual(["#auth-1"]);
    expect(verifierResolution?.didDocument.service?.[0]?.serviceEndpoint).toBe(
      "https://verifier.example/did",
    );
    expect(verifierResolution?.didDocumentMetadata.versionId).toBe("1");
  });

  it("returns null when the trusted subject DID is not present in the DID fixture ledger", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);

    const issuerBundle = harness.evaluateCurrentIssuerDecision(issuer);
    const resolver = createMidnightDidResolver([]);

    await expect(resolver.resolveResult(issuerBundle.subjectDid)).resolves.toBeNull();
  });
});
