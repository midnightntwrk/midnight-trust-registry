import { describe, expect, it } from "vitest";

import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTPayload,
} from "jose";

import {
  buildAuthorizationSubordinateStatementPayload,
  buildFederationLeafConfigurationPayload,
  buildTrustRegistryEntityConfigurationPayload,
  buildTrustRegistryPublicationMetadata,
  buildTrustRegistrySubordinateStatementPayload,
  signEntityStatement,
  verifyEntityStatement,
  verifySimpleTrustChain,
} from "../index.js";
import {
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";

const createSigningFixture = async (kid: string): Promise<{
  alg: string;
  kid: string;
  privateKey: CryptoKey;
  publicJwks: {
    keys: JWK[];
  };
}> => {
  const alg = "EdDSA";
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const publicJwk = await exportJWK(publicKey) as JWK;

  publicJwk.kid = kid;
  publicJwk.alg = alg;
  publicJwk.use = "sig";

  return {
    alg,
    kid,
    privateKey,
    publicJwks: {
      keys: [publicJwk],
    },
  };
};

describe("trust registry OpenID Federation adapter", () => {
  it("builds and verifies a signed registry entity configuration", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const registryKeys = await createSigningFixture("registry-key-1");

    const payload = buildTrustRegistryEntityConfigurationPayload({
      registry: harness.registryRecord,
      publicJwks: registryKeys.publicJwks,
    });
    const jwt = await signEntityStatement({
      payload,
      privateKey: registryKeys.privateKey,
      kid: registryKeys.kid,
      alg: registryKeys.alg,
    });
    const verified = await verifyEntityStatement({
      jwt,
      jwks: registryKeys.publicJwks,
    });

    expect(verified.iss).toBe(harness.registryRecord.serviceEndpoint);
    expect(verified.sub).toBe(harness.registryRecord.serviceEndpoint);
    expect(
      verified.metadata?.midnight_trust_registry?.statement_kind,
    ).toBe("registry");
    expect(
      verified.metadata?.federation_entity?.federation_fetch_endpoint,
    ).toBe(
      `${harness.registryRecord.serviceEndpoint.replace(/\/$/, "")}/federation/fetch`,
    );
  });

  it("does not sign an unanchored status registry hint in issuer metadata", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree-status-hint");
    const registryKeys = await createSigningFixture("registry-key-1");
    harness.authorizeIssuer(issuer);

    const bundle = {
      ...harness.evaluateCurrentIssuerDecision(issuer),
      referencedStatusRegistryId: "status-registry:attacker:v1",
    };
    const payload = buildAuthorizationSubordinateStatementPayload({
      issuerEntityId: harness.registryRecord.serviceEndpoint,
      sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
      subjectPublicJwks: registryKeys.publicJwks,
      bundle,
    });
    const jwt = await signEntityStatement({
      payload,
      privateKey: registryKeys.privateKey,
      kid: registryKeys.kid,
      alg: registryKeys.alg,
    });
    const verified = await verifyEntityStatement({
      jwt,
      jwks: registryKeys.publicJwks,
    });

    expect(payload.metadata?.midnight_trust_registry?.statement_kind).toBe("authorization");
    expect(payload.metadata?.midnight_trust_registry).not.toHaveProperty(
      "referenced_status_registry_id",
    );
    expect(verified.metadata?.midnight_trust_registry).not.toHaveProperty(
      "referenced_status_registry_id",
    );
    const metadata = verified.metadata?.midnight_trust_registry;
    if (metadata?.statement_kind !== "authorization") throw new Error("Expected authorization metadata");
    expect(metadata.status_policy_binding).toEqual(bundle.statusPolicyBinding);
    expect(metadata.status_policy_binding_commitment).toBe(bundle.authorization?.statusPolicyBindingCommitment);
    expect(metadata.authorization_bundle.statusPolicyBinding).toEqual(bundle.statusPolicyBinding);
    expect(metadata.authorization_bundle).not.toHaveProperty("referencedStatusRegistryId");
  });

  it("rejects a substituted status-policy preimage before federation publication", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree-status-substitution");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    if (bundle.statusPolicyBinding === undefined) throw new Error("expected issuer status binding");
    const substituted = {
      ...bundle,
      statusPolicyBinding: {
        ...bundle.statusPolicyBinding,
        statusRegistryId: `0x${"f".repeat(64)}`,
      },
    };
    expect(() => buildTrustRegistryPublicationMetadata({
      registry: harness.registryRecord,
      policyId: harness.policyRecord.policyId,
      policyVersion: harness.policyRecord.version,
      bundle: substituted,
    })).toThrow(/status policy binding does not match governed authorization/i);
    expect(() => buildAuthorizationSubordinateStatementPayload({
      issuerEntityId: harness.registryRecord.serviceEndpoint,
      sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
      subjectPublicJwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: "AA" }] },
      bundle: substituted,
    })).toThrow(/status policy binding does not match governed authorization/i);
    expect(() => buildAuthorizationSubordinateStatementPayload({
      issuerEntityId: harness.registryRecord.serviceEndpoint,
      sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
      subjectPublicJwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: "AA" }] },
      bundle: { ...bundle, statusPolicyBinding: undefined },
    })).toThrow(/status policy binding preimage is missing/i);
  });

  it("rejects signed authorization metadata that disagrees with its evidence bundle", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree-status-metadata-tamper");
    const keys = await createSigningFixture("registry-key-metadata-tamper");
    harness.authorizeIssuer(issuer);
    const payload = buildAuthorizationSubordinateStatementPayload({
      issuerEntityId: harness.registryRecord.serviceEndpoint,
      sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
      subjectPublicJwks: keys.publicJwks,
      bundle: harness.evaluateCurrentIssuerDecision(issuer),
    });
    const metadata = payload.metadata?.midnight_trust_registry;
    if (metadata?.statement_kind !== "authorization") throw new Error("Expected authorization metadata");
    const tampered = {
      ...payload,
      metadata: {
        ...payload.metadata,
        midnight_trust_registry: {
          ...metadata,
          status_policy_binding_commitment: `0x${"f".repeat(64)}`,
        },
      },
    };
    const jwt = await new SignJWT(tampered as JWTPayload)
      .setProtectedHeader({ typ: "entity-statement+jwt", alg: keys.alg, kid: keys.kid })
      .sign(keys.privateKey);

    await expect(verifyEntityStatement({ jwt, jwks: keys.publicJwks }))
      .rejects.toThrow(/authorization metadata does not match its governed evidence bundle/i);
  });

  it("does not turn verifier authorization into an issuer status-policy claim", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("verifier-no-status-claim");
    harness.authorizeVerifier(verifier);
    const bundle = harness.evaluateCurrentVerifierDecision(verifier);
    const payload = buildAuthorizationSubordinateStatementPayload({
      issuerEntityId: harness.registryRecord.serviceEndpoint,
      sourceEndpoint: `${harness.registryRecord.serviceEndpoint}/federation/fetch`,
      subjectPublicJwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: "AA" }] },
      bundle,
    });
    const metadata = payload.metadata?.midnight_trust_registry;
    if (metadata?.statement_kind !== "authorization") throw new Error("Expected authorization metadata");
    expect(metadata.role).toBe("verifier");
    expect(metadata).not.toHaveProperty("status_policy_binding");
    expect(metadata).not.toHaveProperty("status_policy_binding_commitment");
    expect(metadata.authorization_bundle.authorization?.role).toBe("verifier");
  });

  it("builds a signed trust chain for the registry with an embedded authorization bundle", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");
    const anchorKeys = await createSigningFixture("anchor-key-1");
    const registryKeys = await createSigningFixture("registry-key-1");
    const registryEntityId = harness.registryRecord.serviceEndpoint;
    const anchorEntityId = "https://trust-anchor.example";

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);

    const leafPayload = {
      ...buildTrustRegistryEntityConfigurationPayload({
        registry: harness.registryRecord,
        publicJwks: registryKeys.publicJwks,
        authorityHints: [anchorEntityId],
      }),
      metadata: buildTrustRegistryPublicationMetadata({
        registry: harness.registryRecord,
        policyId: harness.policyRecord.policyId,
        policyVersion: harness.policyRecord.version,
        bundle,
      }),
    };
    const subordinatePayload = buildTrustRegistrySubordinateStatementPayload({
      issuerEntityId: anchorEntityId,
      sourceEndpoint: `${anchorEntityId}/federation/fetch`,
      subjectEntityId: registryEntityId,
      subjectPublicJwks: registryKeys.publicJwks,
      registry: harness.registryRecord,
      policyId: harness.policyRecord.policyId,
      policyVersion: harness.policyRecord.version,
      bundle,
    });
    const anchorPayload = buildFederationLeafConfigurationPayload({
      entityId: anchorEntityId,
      publicJwks: anchorKeys.publicJwks,
      authorityHints: [anchorEntityId],
      organizationName: "Midnight Trust Anchor",
      organizationUri: anchorEntityId,
    });

    const chain = await Promise.all([
      signEntityStatement({
        payload: leafPayload,
        privateKey: registryKeys.privateKey,
        kid: registryKeys.kid,
        alg: registryKeys.alg,
      }),
      signEntityStatement({
        payload: subordinatePayload,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
      signEntityStatement({
        payload: anchorPayload,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
    ]);

    const verifiedChain = await verifySimpleTrustChain(chain);
    const subordinate = verifiedChain[1];
    if (subordinate === undefined) {
      throw new Error("expected subordinate statement in trust chain");
    }
    const midnightMetadata = subordinate.metadata?.midnight_trust_registry;

    expect(subordinate.iss).toBe(anchorEntityId);
    expect(subordinate.sub).toBe(registryEntityId);
    expect(midnightMetadata?.statement_kind).toBe("registry-publication");
    if (midnightMetadata?.statement_kind !== "registry-publication") {
      throw new Error("expected registry publication metadata");
    }
    expect(midnightMetadata.registry_id).toBe(harness.registryRecord.registryId);
    expect(midnightMetadata.authorization_bundle?.authorization?.role).toBe(
      "issuer",
    );
    expect(
      midnightMetadata.authorization_bundle?.authorization?.resourceId,
    ).toBe(bundle.authorization?.resourceId);
    expect(bundle.statusPolicyBinding?.statusRegistryId).toBeDefined();
    expect(bundle.authorization?.statusPolicyBindingCommitment).toBeDefined();
    expect(midnightMetadata.authorization_bundle?.referencedStatusRegistryId).toBeUndefined();
    expect(midnightMetadata.authorization_bundle?.referencedStatusPolicyUri).toBeUndefined();

    const rawPeerStatement = {
      ...subordinatePayload,
      metadata: {
        ...subordinatePayload.metadata,
        midnight_trust_registry: {
          ...midnightMetadata,
          authorization_bundle: {
            ...bundle,
            referencedStatusRegistryId: "status-registry:attacker:v1",
            referencedStatusPolicyUri: "https://attacker.example/status-policy",
          },
        },
      },
    };
    const peerJwt = await new SignJWT(rawPeerStatement as JWTPayload)
      .setProtectedHeader({ typ: "entity-statement+jwt", alg: anchorKeys.alg, kid: anchorKeys.kid })
      .sign(anchorKeys.privateKey);
    const peerVerified = await verifyEntityStatement({ jwt: peerJwt, jwks: anchorKeys.publicJwks });
    const peerChain = await verifySimpleTrustChain([chain[0]!, peerJwt, chain[2]!]);
    for (const statement of [peerVerified, peerChain[1]]) {
      const metadata = statement?.metadata?.midnight_trust_registry;
      if (metadata?.statement_kind !== "registry-publication") throw new Error("expected publication metadata");
      expect(metadata.authorization_bundle?.referencedStatusRegistryId).toBeUndefined();
      expect(metadata.authorization_bundle?.referencedStatusPolicyUri).toBeUndefined();
    }
  });

  it("embeds a recognition bundle in signed registry publication metadata", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x");
    const anchorKeys = await createSigningFixture("anchor-key-1");
    const registryKeys = await createSigningFixture("registry-key-1");
    const registryEntityId = harness.registryRecord.serviceEndpoint;
    const anchorEntityId = "https://trust-anchor.example";

    harness.authorizeRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition);

    const leafPayload = {
      ...buildTrustRegistryEntityConfigurationPayload({
        registry: harness.registryRecord,
        publicJwks: registryKeys.publicJwks,
        authorityHints: [anchorEntityId],
      }),
      metadata: buildTrustRegistryPublicationMetadata({
        registry: harness.registryRecord,
        policyId: harness.policyRecord.policyId,
        policyVersion: harness.policyRecord.version,
        bundle,
      }),
    };
    const subordinatePayload = buildTrustRegistrySubordinateStatementPayload({
      issuerEntityId: anchorEntityId,
      sourceEndpoint: `${anchorEntityId}/federation/fetch`,
      subjectEntityId: registryEntityId,
      subjectPublicJwks: registryKeys.publicJwks,
      registry: harness.registryRecord,
      policyId: harness.policyRecord.policyId,
      policyVersion: harness.policyRecord.version,
      bundle,
    });
    const anchorPayload = buildFederationLeafConfigurationPayload({
      entityId: anchorEntityId,
      publicJwks: anchorKeys.publicJwks,
      authorityHints: [anchorEntityId],
      organizationName: "Midnight Trust Anchor",
      organizationUri: anchorEntityId,
    });

    const chain = await Promise.all([
      signEntityStatement({
        payload: leafPayload,
        privateKey: registryKeys.privateKey,
        kid: registryKeys.kid,
        alg: registryKeys.alg,
      }),
      signEntityStatement({
        payload: subordinatePayload,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
      signEntityStatement({
        payload: anchorPayload,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
    ]);

    const verifiedChain = await verifySimpleTrustChain(chain);
    const subordinate = verifiedChain[1];
    if (subordinate === undefined) {
      throw new Error("expected subordinate statement in trust chain");
    }
    const midnightMetadata = subordinate.metadata?.midnight_trust_registry;
    expect(midnightMetadata?.statement_kind).toBe("registry-publication");
    if (midnightMetadata?.statement_kind !== "registry-publication") {
      throw new Error("expected registry publication metadata");
    }
    expect(
      midnightMetadata.recognition_bundle?.recognition?.recognizedRegistryId,
    ).toBe(
      recognition.recognizedRegistryId,
    );
    expect(
      midnightMetadata.recognition_bundle?.recognition?.scope.resourceType,
    ).toBe(
      recognition.scopeResourceType,
    );
  });

  it("rejects a malformed trust chain when authority hints break the superior link", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");
    const anchorKeys = await createSigningFixture("anchor-key-1");
    const registryKeys = await createSigningFixture("registry-key-1");
    const registryEntityId = harness.registryRecord.serviceEndpoint;
    const anchorEntityId = "https://trust-anchor.example";

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);

    const malformedLeaf = buildFederationLeafConfigurationPayload({
      entityId: registryEntityId,
      publicJwks: registryKeys.publicJwks,
      authorityHints: ["https://other.example/federation"],
    });
    const subordinate = buildTrustRegistrySubordinateStatementPayload({
      issuerEntityId: anchorEntityId,
      sourceEndpoint: `${anchorEntityId}/federation/fetch`,
      subjectEntityId: registryEntityId,
      subjectPublicJwks: registryKeys.publicJwks,
      registry: harness.registryRecord,
      policyId: harness.policyRecord.policyId,
      policyVersion: harness.policyRecord.version,
      bundle,
    });
    const anchorPayload = buildFederationLeafConfigurationPayload({
      entityId: anchorEntityId,
      publicJwks: anchorKeys.publicJwks,
      authorityHints: [anchorEntityId],
      organizationName: "Midnight Trust Anchor",
      organizationUri: anchorEntityId,
    });

    const chain = await Promise.all([
      signEntityStatement({
        payload: malformedLeaf,
        privateKey: registryKeys.privateKey,
        kid: registryKeys.kid,
        alg: registryKeys.alg,
      }),
      signEntityStatement({
        payload: subordinate,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
      signEntityStatement({
        payload: anchorPayload,
        privateKey: anchorKeys.privateKey,
        kid: anchorKeys.kid,
        alg: anchorKeys.alg,
      }),
    ]);

    await expect(verifySimpleTrustChain(chain)).rejects.toThrow(
      /authority_hints/i,
    );
  });
});
