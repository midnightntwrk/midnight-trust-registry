import { Buffer } from "node:buffer";

import {
  createMidnightDIDHolderBinding,
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKey, deriveJubjubPublicKeyFromSeed, encodeJubjubSignature, signApplicationEvidenceCommitmentFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationScopeSchema,
  computeAuthorizationScopeCommitment,
  sha256Hex,
  type AuthorizationScope,
  type IssuerStatusPolicyBinding,
} from "@midnight-ntwrk/trust-registry-domain";

import { type ApplicationVpMaterial, type QualifiedApplicationVpContext, type QualifiedApplicationVpFamilyAdapter } from "./application-vp-verifier.js";
import { applicationStatusAttestationDigest, createAttestedApplicationStatusSource, type SignedApplicationStatusStatement } from "./application-status-attestation.js";
import { decodeApplicationVpProof, encodeApplicationVpProof } from "./application-vp-proof-json.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "./did-resolution.js";
import { createIssuerAuthorizationScopeFixture, createIssuerScenarioFixture, createMidnightDid } from "./fixtures.js";

export const VP_FIXTURE_TIME_MS = Date.parse("2026-05-20T00:01:00.000Z");
export const VP_FIXTURE_NONCE = `0x${"11".repeat(32)}`;
export const VP_FIXTURE_TRUST_CONTEXT = {
  registryId: "registry:vp-fixture",
  genesisHash: `0x${"12".repeat(32)}`,
  contractAddress: `0x${"13".repeat(32)}`,
  origin: "http://127.0.0.1:4400",
};

const bytes32 = (value: string): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

type FixtureCredentialBody = {
  version: "tr-vp-fixture-v1";
  issuerDid: string;
  issuerMethodId: string;
  subjectDid: string;
  holderMethodId: string;
  scope: AuthorizationScope;
  claimsCommitment: string;
  statusRegistryId: string;
  statusAuthorityMethod: string;
  statusHandleCommitment: string;
  credentialExpiresAtMs: number;
};

type FixturePresentationBody = {
  version: "tr-vp-presentation-fixture-v1";
  subjectDid: string;
  credentialBodyRoot: string;
  privatePayload: string;
  audience: string;
  registryId: string;
  genesisHash: string;
  contractAddress: string;
  nonce: string;
  role: AuthorizationScope["role"];
  scopeCommitment: string;
  policyId: string;
  policyVersion: string;
};

const parseFixtureCredentialBody = (raw: string): FixtureCredentialBody => {
  const value: unknown = JSON.parse(raw);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Application VP fixture credential body is invalid");
  }
  const body = value as Record<string, unknown>;
  const keys = [
    "version", "issuerDid", "issuerMethodId", "subjectDid", "holderMethodId", "scope",
    "claimsCommitment", "statusRegistryId", "statusAuthorityMethod", "statusHandleCommitment", "credentialExpiresAtMs",
  ];
  if (
    Object.keys(body).length !== keys.length || keys.some((key) => !Object.hasOwn(body, key))
    || body.version !== "tr-vp-fixture-v1"
    || typeof body.issuerDid !== "string" || typeof body.issuerMethodId !== "string"
    || typeof body.subjectDid !== "string" || typeof body.holderMethodId !== "string"
    || typeof body.claimsCommitment !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.claimsCommitment)
    || typeof body.statusRegistryId !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.statusRegistryId)
    || typeof body.statusAuthorityMethod !== "string"
    || typeof body.statusHandleCommitment !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.statusHandleCommitment)
    || typeof body.credentialExpiresAtMs !== "number" || !Number.isSafeInteger(body.credentialExpiresAtMs)
  ) throw new TypeError("Application VP fixture credential body is invalid");
  return {
    version: "tr-vp-fixture-v1",
    issuerDid: body.issuerDid,
    issuerMethodId: body.issuerMethodId,
    subjectDid: body.subjectDid,
    holderMethodId: body.holderMethodId,
    scope: AuthorizationScopeSchema.parse(body.scope),
    claimsCommitment: body.claimsCommitment,
    statusRegistryId: body.statusRegistryId,
    statusAuthorityMethod: body.statusAuthorityMethod,
    statusHandleCommitment: body.statusHandleCommitment,
    credentialExpiresAtMs: body.credentialExpiresAtMs,
  };
};

const parseFixturePresentationBody = (raw: string): FixturePresentationBody => {
  const value: unknown = JSON.parse(raw);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Application VP fixture presentation body is invalid");
  }
  const body = value as Record<string, unknown>;
  if (
    Object.keys(body).length !== 13
    || !["version", "subjectDid", "credentialBodyRoot", "privatePayload", "audience", "registryId",
      "genesisHash", "contractAddress", "nonce", "role", "scopeCommitment", "policyId", "policyVersion"]
      .every((key) => Object.hasOwn(body, key))
    || body.version !== "tr-vp-presentation-fixture-v1"
    || typeof body.subjectDid !== "string"
    || typeof body.credentialBodyRoot !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.credentialBodyRoot)
    || typeof body.privatePayload !== "string" || body.privatePayload.length === 0
    || typeof body.audience !== "string" || typeof body.registryId !== "string"
    || typeof body.genesisHash !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.genesisHash)
    || typeof body.contractAddress !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.contractAddress)
    || typeof body.nonce !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.nonce)
    || !["issuer", "verifier", "auditor", "maintainer"].includes(String(body.role))
    || typeof body.scopeCommitment !== "string" || !/^0x[0-9a-f]{64}$/u.test(body.scopeCommitment)
    || typeof body.policyId !== "string" || typeof body.policyVersion !== "string"
  ) throw new TypeError("Application VP fixture presentation body is invalid");
  return body as FixturePresentationBody;
};

type FixtureStatusDecision = {
  registryId: string;
  authorityMethod: string;
  statusHandleCommitment: string;
  active: boolean;
  validUntilMs: number;
};

/** Local proof fixture with published VC signatures and a DID-signed status attestation by default. */
export async function createApplicationVpScenarioFixture(
  nonce = VP_FIXTURE_NONCE,
  options: {
    issuerDid?: string;
    issuerSecret?: bigint;
    issuerDidVersion?: bigint;
    statusPolicyBinding?: IssuerStatusPolicyBinding;
    subjectDid?: string;
    evidenceVerifierDid?: string;
    evidenceVerifierMethodId?: string;
    scope?: AuthorizationScope;
    trustContext?: QualifiedApplicationVpContext;
    policyId?: string;
    policyVersion?: string;
    statusDecision?: Partial<FixtureStatusDecision>;
    presentationCredentialBodyRoot?: string;
    presentationContext?: Partial<Omit<FixturePresentationBody, "version" | "subjectDid" | "credentialBodyRoot" | "privatePayload">>;
  } = {},
) {
  const trustContext = options.trustContext ?? VP_FIXTURE_TRUST_CONTEXT;
  const issuerDid = options.issuerDid ?? createMidnightDid("vp-issuer");
  const subjectDid = options.subjectDid ?? createMidnightDid("vp-holder");
  const evidenceVerifierDid = options.evidenceVerifierDid ?? createMidnightDid("vp-evidence-verifier");
  const evidenceVerifierMethodId = options.evidenceVerifierMethodId ?? "assertion-1";
  const issuerSecret = options.issuerSecret ?? 19n;
  const statusAuthorityMethod = options.statusPolicyBinding?.statusAuthorityVerificationMethod
    ?? `${issuerDid}#assertion-1`;
  if (!statusAuthorityMethod.startsWith(`${issuerDid}#`)) {
    throw new Error("VP fixture status authority method must belong to its issuer DID");
  }
  const statusMethodId = statusAuthorityMethod.slice(issuerDid.length + 1);
  const statusRegistryId = options.statusPolicyBinding?.statusRegistryId ?? hex(bytes32("status-registry"));
  const holderSecret = 23n;
  const subjectAssertionSecret = 29n;
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(issuerDid, {
      schnorrJubjubAssertionMethods: [
        { id: "assertion-1", publicKey: deriveJubjubPublicKey(issuerSecret) },
        ...(statusMethodId === "assertion-1" ? [] : [{ id: statusMethodId, publicKey: deriveJubjubPublicKey(issuerSecret) }]),
      ],
      ...(options.issuerDidVersion === undefined ? {} : { version: options.issuerDidVersion }),
    }),
    createMidnightDidLedgerFixture(subjectDid, {
      schnorrJubjubAuthenticationMethods: [
        { id: "auth-1", publicKey: deriveJubjubPublicKey(holderSecret) },
      ],
      schnorrJubjubAssertionMethods: [
        { id: "assertion-1", publicKey: deriveJubjubPublicKey(subjectAssertionSecret) },
      ],
    }),
    createMidnightDidLedgerFixture(evidenceVerifierDid, {
      verificationMethodId: evidenceVerifierMethodId,
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(41)),
    }),
  ]);
  const issuerMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(issuerDid),
    verificationMethodId: "#assertion-1",
    relationship: "assertionMethod",
  });
  const statusMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(issuerDid),
    verificationMethodId: statusAuthorityMethod,
    relationship: "assertionMethod",
  });
  const holderMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(subjectDid),
    verificationMethodId: "#auth-1",
    relationship: "authentication",
  });
  const subjectAssertionMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(subjectDid),
    verificationMethodId: "#assertion-1",
    relationship: "assertionMethod",
  });
  const scope = AuthorizationScopeSchema.parse(
    options.scope ?? createIssuerAuthorizationScopeFixture(createIssuerScenarioFixture("vp")),
  );
  const credentialBody: FixtureCredentialBody = {
    version: "tr-vp-fixture-v1",
    issuerDid,
    issuerMethodId: "#assertion-1",
    subjectDid,
    holderMethodId: "#auth-1",
    scope,
    claimsCommitment: sha256Hex(`accepted-${scope.role}-claims`),
    statusRegistryId,
    statusAuthorityMethod,
    statusHandleCommitment: hex(bytes32("credential-status-handle")),
    credentialExpiresAtMs: VP_FIXTURE_TIME_MS + 60 * 60_000,
  };
  const rawCredentialBody = JSON.stringify(credentialBody);
  const credentialBodyRoot = bytes32(rawCredentialBody);
  const presentationBody: FixturePresentationBody = {
    version: "tr-vp-presentation-fixture-v1",
    subjectDid,
    credentialBodyRoot: options.presentationCredentialBodyRoot ?? hex(credentialBodyRoot),
    privatePayload: "private-presentation-payload",
    audience: trustContext.origin,
    registryId: trustContext.registryId,
    genesisHash: trustContext.genesisHash,
    contractAddress: trustContext.contractAddress,
    nonce,
    role: scope.role,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    policyId: options.policyId ?? "policy:vp:v1",
    policyVersion: options.policyVersion ?? "v1",
    ...options.presentationContext,
  };
  const rawPresentationBody = JSON.stringify(presentationBody);
  const presentationBodyRoot = bytes32(rawPresentationBody);
  const challengeHash = Buffer.from(sha256Hex(Buffer.from(nonce.slice(2), "hex")).slice(2), "hex");
  const holderBinding = createMidnightDIDHolderBinding(holderMethod).explicitBinding;
  const material: ApplicationVpMaterial = {
    issuerDid,
    issuerMethodId: "#assertion-1",
    subjectDid,
    holderMethodId: "#auth-1",
    credentialProof: signMidnightDIDCredentialProof({
      methodBinding: issuerMethod,
      secretScalar: issuerSecret,
      bodyRoot: credentialBodyRoot,
      createdAt: BigInt(VP_FIXTURE_TIME_MS - 60_000),
      challengeHash: bytes32("issuance-challenge"),
    }),
    presentationProof: signMidnightDIDPresentationProof({
      methodBinding: holderMethod,
      secretScalar: holderSecret,
      bodyRoot: presentationBodyRoot,
      createdAt: BigInt(VP_FIXTURE_TIME_MS),
      challengeHash,
    }),
    credentialBodyRoot,
    presentationBodyRoot,
    credentialHolderBinding: holderBinding,
    presentationHolderBinding: holderBinding,
    statusBinding: {
      registryRef: {
        registryId: Buffer.from(statusRegistryId.slice(2), "hex"),
        authorityVerificationMethodRef: statusMethod.verificationMethodRef,
      },
      statusHandleCommitment: bytes32("credential-status-handle"),
    },
    credentialExpiresAtMs: VP_FIXTURE_TIME_MS + 60 * 60_000,
  };
  const submission = {
    rawCredentialBody,
    rawPresentationBody,
    credentialProof: encodeApplicationVpProof(material.credentialProof),
    presentationProof: encodeApplicationVpProof(material.presentationProof),
  };
  const submittedBodies = new Map<string, FixtureCredentialBody>();
  submittedBodies.set(hex(material.credentialBodyRoot), credentialBody);
  const submittedPresentations = new Map<string, FixturePresentationBody>();
  submittedPresentations.set(hex(material.presentationBodyRoot), presentationBody);
  const statusDecision: FixtureStatusDecision = {
    registryId: credentialBody.statusRegistryId,
    authorityMethod: credentialBody.statusAuthorityMethod,
    statusHandleCommitment: credentialBody.statusHandleCommitment,
    active: true,
    validUntilMs: VP_FIXTURE_TIME_MS + 15 * 60_000,
    ...options.statusDecision,
  };
  const statusStatement = {
    version: "tr-application-status-attestation-v1" as const,
    statusRegistryId: credentialBody.statusRegistryId,
    statusAuthorityMethodId: credentialBody.statusAuthorityMethod,
    statusHandleCommitment: credentialBody.statusHandleCommitment,
    credentialBodyRoot: hex(credentialBodyRoot),
    challengeHash: sha256Hex(Buffer.from(nonce.slice(2), "hex")),
    active: true,
    observedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
    expiresAt: new Date(VP_FIXTURE_TIME_MS + 5 * 60_000).toISOString(),
  };
  const signedStatusAttestation = {
    statement: statusStatement,
    proof: {
      verificationMethodId: credentialBody.statusAuthorityMethod,
      algorithm: "jubjub-schnorr" as const,
      signature: hex(encodeJubjubSignature(signJubjubDigest(
        issuerSecret,
        applicationStatusAttestationDigest(statusStatement),
      ))),
    },
  };
  const fixtureStatusPolicyBinding: IssuerStatusPolicyBinding = options.statusPolicyBinding ?? {
    version: "tr-issuer-status-policy-v1",
    trustRegistryId: trustContext.registryId,
    issuerAuthorizationId: "auth:issuer:vp-fixture",
    statusRegistryId: credentialBody.statusRegistryId,
    statusAuthorityVerificationMethod: credentialBody.statusAuthorityMethod,
    statusPolicyId: "policy:vp-fixture-status",
    statusPolicyVersion: "v1",
    statusPolicyContentCommitment: sha256Hex("vp-fixture-status-policy"),
  };
  const statusWitnesses = new Map<string, SignedApplicationStatusStatement>();
  const attestedStatus = createAttestedApplicationStatusSource({
    resolver,
    fetchAttestation: async (request) => {
      if (request.statusRegistryId !== credentialBody.statusRegistryId
        || request.statusHandleCommitment !== credentialBody.statusHandleCommitment
        || request.credentialBodyRoot !== hex(credentialBodyRoot)) {
        throw new Error("Fixture status authority refuses an unknown credential binding");
      }
      const statement = { ...statusStatement, challengeHash: request.challengeHash };
      const witness = {
        statement,
        proof: {
          ...signedStatusAttestation.proof,
          signature: hex(encodeJubjubSignature(signJubjubDigest(
            issuerSecret,
            applicationStatusAttestationDigest(statement),
          ))),
        },
      };
      statusWitnesses.set(request.challengeHash, witness);
      return witness;
    },
  });
  const family: QualifiedApplicationVpFamilyAdapter<typeof submission> = {
    prepare: async (submitted) => {
      if (
        submitted === null || typeof submitted !== "object" || Array.isArray(submitted)
        || Object.keys(submitted).length !== 4
        || !Object.hasOwn(submitted, "rawCredentialBody")
        || !Object.hasOwn(submitted, "rawPresentationBody")
        || !Object.hasOwn(submitted, "credentialProof")
        || !Object.hasOwn(submitted, "presentationProof")
        || typeof submitted.rawCredentialBody !== "string"
        || typeof submitted.rawPresentationBody !== "string"
        || submitted.rawCredentialBody.length === 0 || submitted.rawCredentialBody.length > 16_384
        || submitted.rawPresentationBody.length === 0 || submitted.rawPresentationBody.length > 16_384
      ) throw new TypeError("Application VP fixture submission is invalid");
      const body = parseFixtureCredentialBody(submitted.rawCredentialBody);
      const presentation = parseFixturePresentationBody(submitted.rawPresentationBody);
      const prepared = {
        ...material,
        issuerDid: body.issuerDid,
        issuerMethodId: body.issuerMethodId,
        subjectDid: body.subjectDid,
        holderMethodId: body.holderMethodId,
        credentialExpiresAtMs: body.credentialExpiresAtMs,
        credentialBodyRoot: bytes32(submitted.rawCredentialBody),
        presentationBodyRoot: bytes32(submitted.rawPresentationBody),
        credentialProof: decodeApplicationVpProof(submitted.credentialProof),
        presentationProof: decodeApplicationVpProof(submitted.presentationProof),
      };
      submittedBodies.set(hex(prepared.credentialBodyRoot), body);
      submittedPresentations.set(hex(prepared.presentationBodyRoot), presentation);
      return prepared;
    },
    assertCredentialBodyBinding: async (prepared) => {
      const body = submittedBodies.get(hex(prepared.credentialBodyRoot));
      const presentation = submittedPresentations.get(hex(prepared.presentationBodyRoot));
      if (
        !body || !presentation
        || presentation.subjectDid !== prepared.subjectDid
        || presentation.credentialBodyRoot !== hex(prepared.credentialBodyRoot)
        || body.issuerDid !== prepared.issuerDid || body.issuerMethodId !== prepared.issuerMethodId
        || body.subjectDid !== prepared.subjectDid || body.holderMethodId !== prepared.holderMethodId
        || body.credentialExpiresAtMs !== prepared.credentialExpiresAtMs
        || body.statusRegistryId !== hex(prepared.statusBinding.registryRef.registryId)
        || body.statusAuthorityMethod !== statusAuthorityMethod
        || !equalMethodRef(
          prepared.statusBinding.registryRef.authorityVerificationMethodRef,
          statusMethod.verificationMethodRef,
        )
        || body.statusHandleCommitment !== hex(prepared.statusBinding.statusHandleCommitment)
      ) throw new TypeError("Application VP fixture credential binding is invalid");
      return true as const;
    },
    assertIssuerEligible: async (prepared) => {
      if (prepared.issuerDid !== issuerDid) throw new TypeError("Application VP fixture issuer is ineligible");
      return fixtureStatusPolicyBinding;
    },
    assertStatusActive: async (prepared, binding, context) => {
      const body = submittedBodies.get(hex(prepared.credentialBodyRoot));
      if (!body) throw new TypeError("Application VP fixture credential is missing");
      if (options.statusDecision) {
        if (!statusDecision.active
          || statusDecision.registryId !== body.statusRegistryId
          || statusDecision.authorityMethod !== body.statusAuthorityMethod
          || statusDecision.statusHandleCommitment !== body.statusHandleCommitment
        ) throw new TypeError("Application VP fixture status is not active under the signed binding");
        return {
          validUntilMs: statusDecision.validUntilMs,
          statusDecisionCommitment: sha256Hex(JSON.stringify(["tr:fixture:status-decision:v1", statusDecision])),
        };
      }
      return attestedStatus({ material: prepared, binding, ...context });
    },
    assertRoleClaims: async (prepared) => {
      const body = submittedBodies.get(hex(prepared.credentialBodyRoot));
      if (!body) throw new TypeError("Application VP fixture claims are missing");
      return {
        claimsCommitment: body.claimsCommitment,
        scopeCommitment: computeAuthorizationScopeCommitment(body.scope),
      };
    },
    assertPresentationBinding: async (prepared, expected) => {
      const presentation = submittedPresentations.get(hex(prepared.presentationBodyRoot));
      if (!presentation
        || presentation.subjectDid !== expected.subjectDid
        || presentation.audience !== expected.origin
        || presentation.registryId !== expected.registryId
        || presentation.genesisHash !== expected.genesisHash
        || presentation.contractAddress !== expected.contractAddress
        || presentation.nonce !== expected.nonce
        || presentation.role !== expected.role
        || presentation.scopeCommitment !== expected.scopeCommitment
        || presentation.policyId !== expected.policyId
        || presentation.policyVersion !== expected.policyVersion) {
        throw new TypeError("Application VP fixture presentation context is invalid");
      }
      return true as const;
    },
  };
  const verifierSeed = new Uint8Array(32).fill(41);
  const signer = {
    did: evidenceVerifierDid,
    keyId: `${evidenceVerifierDid}#${evidenceVerifierMethodId}`,
    publicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
    signCommitment: (keyId: Uint8Array, commitment: Uint8Array) =>
      signApplicationEvidenceCommitmentFromSeed(verifierSeed, keyId, commitment),
  };
  return {
    input: {
      submission,
      nonce,
      expectedSubjectDid: subjectDid,
      scope,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
      resolver,
      family,
    },
    material,
    family,
    signer,
    subjectAuthentication: { method: holderMethod, secretScalar: holderSecret },
    subjectAssertion: { method: subjectAssertionMethod, secretScalar: subjectAssertionSecret },
    signedStatusAttestation,
    readStatusWitness: (challengeHash: string): SignedApplicationStatusStatement | null => {
      const witness = statusWitnesses.get(challengeHash);
      return witness === undefined ? null : structuredClone(witness);
    },
    fixtureStatusPolicyBinding,
  };
}

function equalMethodRef(
  left: { controllerAddress: { bytes: Uint8Array }; methodId: Uint8Array },
  right: { controllerAddress: { bytes: Uint8Array }; methodId: Uint8Array },
): boolean {
  return Buffer.from(left.controllerAddress.bytes).equals(Buffer.from(right.controllerAddress.bytes))
    && Buffer.from(left.methodId).equals(Buffer.from(right.methodId));
}
