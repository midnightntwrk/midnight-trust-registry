import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  AuthorizationState,
  pureCircuits,
  SignerRole,
  VerificationRelationship,
} from "@midnight-ntwrk/credential-compact";
import {
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  createMidnightDid,
  pinnedVcAuthority,
  vcAuthorityDomainCommitment,
  vcAuthorityDomainFields,
} from "@midnight-ntwrk/trust-registry-integration";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/u.test(version ?? "")) {
  throw new Error("Expected a pinned stable Compact compiler version");
}

const fixtureBytes = (label) => createHash("sha256").update(label).digest();
const fixtureProof = (seed, methodRef, bodyRoot, createdAt, challengeCircuit) => {
  const secret = seedBytesToJubjubSecretScalar(seed);
  const nonce = seedBytesToJubjubSecretScalar(createHash("sha256")
    .update("packed-vc-test-nonce")
    .update(seed)
    .update(bodyRoot)
    .update(String(createdAt))
    .update(challengeCircuit.name)
    .digest());
  if (nonce === 0n) throw new Error("Fixture nonce must be nonzero");
  const unsigned = {
    signerVerificationMethodRef: methodRef,
    createdAt,
    challengeHash: createHash("sha256")
      .update("packed-vc-test-challenge")
      .update(bodyRoot)
      .update(String(createdAt))
      .update(challengeCircuit.name)
      .digest(),
    publicKey: deriveJubjubPublicKey(secret),
    signature: { r: deriveJubjubPublicKey(nonce), s: 0n },
  };
  return {
    ...unsigned,
    signature: {
      r: unsigned.signature.r,
      s: normalizeScalar(nonce + challengeCircuit(bodyRoot, unsigned) * secret),
    },
  };
};

const fixture = fileURLToPath(import.meta.resolve(
  "@midnight-ntwrk/trust-registry-integration/fixtures/vc-authority-consumer.compact",
));
const vcCompactRoot = dirname(fileURLToPath(import.meta.resolve(
  "@midnight-ntwrk/credential-compact/credentials/composable.compact",
)));
const cacheRoot = join(process.cwd(), "node_modules/.cache");
mkdirSync(cacheRoot, { recursive: true });
const output = mkdtempSync(join(cacheRoot, "packed-vc-consumer-"));

try {
  const compile = spawnSync("compact", [
    "compile", `+${version}`, "--skip-zk", "--compact-path", vcCompactRoot, fixture, output,
  ], { encoding: "utf8" });
  if (compile.error) throw compile.error;
  assert.equal(compile.status, 0, compile.stderr);

  const compiled = await import(pathToFileURL(join(output, "contract/index.js")).href);
  const authorityDid = createMidnightDid("packed-vc-consumer-authority");
  const domain = {
    networkId: "undeployed",
    consumerContractAddress: `0x${"11".repeat(32)}`,
    registryId: "registry:packed-vc-consumer:trusted",
    registryContractAddress: `0x${"22".repeat(32)}`,
    authorityDid,
    authorityMethodId: `${authorityDid}#authority-1`,
  };
  const fields = vcAuthorityDomainFields(domain);
  assert.deepEqual(
    compiled.pureCircuits.authorityDomainCommitment(fields),
    vcAuthorityDomainCommitment(domain),
  );
  const authoritySeed = new Uint8Array(32).fill(17);
  const publicKey = deriveJubjubPublicKeyFromSeed(authoritySeed);
  const contract = new compiled.Contract({});
  const initial = await contract.initialState(
    createConstructorContext({}, "0".repeat(64)),
    pinnedVcAuthority({ domain, publicKey }),
    fields,
  );
  const contractAddress = domain.consumerContractAddress.slice(2);
  const circuitContextFor = (circuitId, state) => {
    const call = state.callContext ?? state;
    return createCircuitContext({
      circuitId,
      contractAddress,
      coinPublicKeyOrZswapState: call.currentZswapLocalState,
      contractState: call.currentQueryContext?.state ?? call.currentContractState,
      privateState: call.currentPrivateState,
    });
  };
  let circuitContext = circuitContextFor("installSignerAuthorization", initial);
  assert.deepEqual(
    (await compiled.ledger(circuitContext.callContext.currentQueryContext.state)).pinnedDomain.networkIdCommitment,
    fields.networkIdCommitment,
  );
  await assert.rejects(() => contract.initialState(
    createConstructorContext({}, "0".repeat(64)),
    pinnedVcAuthority({ domain: { ...domain, registryId: "registry:other:trusted" }, publicKey }),
    fields,
  ), /domain preimage mismatch/i);

  const authority = pinnedVcAuthority({ domain, publicKey });
  const issuerSeed = new Uint8Array(32).fill(49);
  const issuerMethodRef = {
    controllerAddress: authority.verificationMethodRef.controllerAddress,
    methodId: fixtureBytes("packed-vc-issuer-method"),
  };
  const schema = {
    packageId: fixtureBytes("packed-vc-package"),
    schemaId: fixtureBytes("packed-vc-schema"),
    majorVersion: 1n,
    minorVersion: 0n,
  };
  const issuer = {
    version: 1n,
    authorizationId: fixtureBytes("packed-vc-issuer-authorization"),
    decisionSequence: 1n,
    state: AuthorizationState.active,
    role: SignerRole.issuer,
    signerVerificationMethodRef: issuerMethodRef,
    signerPublicKey: deriveJubjubPublicKeyFromSeed(issuerSeed),
    didStateVersion: 2n,
    verificationRelationship: VerificationRelationship.assertionMethod,
    scopeCommitment: pureCircuits.issuerScopeCommitment(schema),
    policyCommitment: fixtureBytes("packed-vc-policy"),
  };
  const authorityProofFor = (descriptor) => fixtureProof(
    authoritySeed,
    authority.verificationMethodRef,
    pureCircuits.signerAuthorizationDecisionRoot(descriptor, authority.domainCommitment),
    descriptor.decisionSequence,
    pureCircuits.signerAuthorizationProofChallenge,
  );
  const issuerProof = authorityProofFor(issuer);
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContext,
    issuer,
    { ...issuerProof, signature: { ...issuerProof.signature, s: issuerProof.signature.s + 1n } },
  ), /Signature verification failed/i);
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContext,
    issuer,
    { ...issuerProof, signerVerificationMethodRef: {
      ...issuerProof.signerVerificationMethodRef,
      methodId: fixtureBytes("other-authority-method"),
    } },
  ), /Authorization proof method does not match authority/i);
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContext,
    issuer,
    { ...issuerProof, publicKey: deriveJubjubPublicKeyFromSeed(issuerSeed) },
  ), /Jubjub points do not match/i);
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContext,
    issuer,
    fixtureProof(
      authoritySeed,
      authority.verificationMethodRef,
      pureCircuits.signerAuthorizationDecisionRoot(issuer, fixtureBytes("wrong-authority-domain")),
      issuer.decisionSequence,
      pureCircuits.signerAuthorizationProofChallenge,
    ),
  ), /Signature verification failed/i);
  const installedIssuer = await contract.circuits.installSignerAuthorization(circuitContext, issuer, issuerProof);
  circuitContext = circuitContextFor("installSignerAuthorization", installedIssuer.context.callContext);
  assert.equal(
    (await compiled.ledger(circuitContext.callContext.currentQueryContext.state))
      .installedSigners.lookup(issuer.authorizationId).decisionSequence,
    issuer.decisionSequence,
  );
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContext, issuer, issuerProof,
  ), /sequence must increase/i);

  const credential = {
    version: 1n,
    schema,
    issuerVerificationMethodRef: issuerMethodRef,
    holderBinding: { holderVerificationMethodRef: issuerMethodRef },
    statusBinding: {},
    issuedAt: 1n,
    hasExpiration: false,
    expiresAt: 0n,
    claims: {},
    claimCommitments: {},
    claimRoot: fixtureBytes("packed-vc-claim"),
  };
  const credentialProof = fixtureProof(
    issuerSeed,
    issuerMethodRef,
    compiled.pureCircuits.credentialBodyRoot(credential),
    1n,
    pureCircuits.issuanceProofChallenge,
  );
  await contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContextFor("assertIssuerCredentialSchemaSignerProof", circuitContext),
    credential, credentialProof, issuer.authorizationId,
  );
  await assert.rejects(() => contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContextFor("assertIssuerCredentialSchemaSignerProof", circuitContext),
    credential,
    { ...credentialProof, signature: { ...credentialProof.signature, s: credentialProof.signature.s + 1n } },
    issuer.authorizationId,
  ), /Signature verification failed/i);
  await assert.rejects(() => contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContextFor("assertIssuerCredentialSchemaSignerProof", circuitContext), credential,
    { ...credentialProof, signerVerificationMethodRef: {
      ...credentialProof.signerVerificationMethodRef,
      methodId: fixtureBytes("other-issuer-method"),
    } },
    issuer.authorizationId,
  ), /Proof signer method does not match authorization/i);
  await assert.rejects(() => contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContextFor("assertIssuerCredentialSchemaSignerProof", circuitContext), credential,
    { ...credentialProof, publicKey: deriveJubjubPublicKeyFromSeed(authoritySeed) },
    issuer.authorizationId,
  ), /Jubjub points do not match/i);
  const wrongSchemaCredential = {
    ...credential,
    schema: { ...schema, schemaId: fixtureBytes("other-schema") },
  };
  await assert.rejects(() => contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContextFor("assertIssuerCredentialSchemaSignerProof", circuitContext),
    wrongSchemaCredential,
    fixtureProof(
      issuerSeed,
      issuerMethodRef,
      compiled.pureCircuits.credentialBodyRoot(wrongSchemaCredential),
      1n,
      pureCircuits.issuanceProofChallenge,
    ),
    issuer.authorizationId,
  ), /Issuer authorization scope does not match schema/i);

  const verifierSeed = new Uint8Array(32).fill(51);
  const requestScopeCommitment = fixtureBytes("packed-vc-request-scope");
  const verifierMethodRef = {
    controllerAddress: authority.verificationMethodRef.controllerAddress,
    methodId: fixtureBytes("packed-vc-verifier-method"),
  };
  const verifier = {
    ...issuer,
    authorizationId: fixtureBytes("packed-vc-verifier-authorization"),
    role: SignerRole.verifier,
    signerVerificationMethodRef: verifierMethodRef,
    signerPublicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
    verificationRelationship: VerificationRelationship.authentication,
    scopeCommitment: requestScopeCommitment,
  };
  const installedVerifier = await contract.circuits.installSignerAuthorization(
    circuitContext, verifier, authorityProofFor(verifier),
  );
  circuitContext = circuitContextFor("assertVerifierRequestAuthorized", installedVerifier.context.callContext);
  const requestProof = fixtureProof(
    verifierSeed, verifierMethodRef, requestScopeCommitment, 1n,
    pureCircuits.verifierRequestProofChallenge,
  );
  await contract.circuits.assertVerifierRequestAuthorized(
    circuitContext, requestScopeCommitment, requestProof, verifier.authorizationId,
  );
  await assert.rejects(() => contract.circuits.assertVerifierRequestAuthorized(
    circuitContext, fixtureBytes("wrong-request-scope"), requestProof, verifier.authorizationId,
  ), /Verifier authorization scope does not match request/i);
  await assert.rejects(() => contract.circuits.assertVerifierRequestAuthorized(
    circuitContext,
    requestScopeCommitment,
    { ...requestProof, signerVerificationMethodRef: {
      ...requestProof.signerVerificationMethodRef,
      methodId: fixtureBytes("other-verifier-method"),
    } },
    verifier.authorizationId,
  ), /Proof signer method does not match authorization/i);
  await assert.rejects(() => contract.circuits.assertVerifierRequestAuthorized(
    circuitContext,
    requestScopeCommitment,
    { ...requestProof, publicKey: deriveJubjubPublicKeyFromSeed(issuerSeed) },
    verifier.authorizationId,
  ), /Jubjub points do not match/i);

  const rolledBackIssuer = { ...issuer, decisionSequence: 2n, didStateVersion: 1n };
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContextFor("installSignerAuthorization", circuitContext),
    rolledBackIssuer, authorityProofFor(rolledBackIssuer),
  ), /DID state version must not decrease/i);
  const revokedIssuer = { ...issuer, decisionSequence: 2n, state: AuthorizationState.revoked };
  const installedRevocation = await contract.circuits.installSignerAuthorization(
    circuitContextFor("installSignerAuthorization", circuitContext),
    revokedIssuer, authorityProofFor(revokedIssuer),
  );
  circuitContext = circuitContextFor("assertIssuerCredentialSchemaSignerProof", installedRevocation.context.callContext);
  await assert.rejects(() => contract.circuits.assertIssuerCredentialSchemaSignerProof(
    circuitContext, credential, credentialProof, issuer.authorizationId,
  ), /Signer authorization must be active/i);
  const revivedIssuer = { ...issuer, decisionSequence: 3n };
  await assert.rejects(() => contract.circuits.installSignerAuthorization(
    circuitContextFor("installSignerAuthorization", circuitContext),
    revivedIssuer, authorityProofFor(revivedIssuer),
  ), /Revoked signer authorization must remain revoked/i);

  console.log("[packed-vc-consumer] Ledger 9 fixture accepted issuer/verifier proofs and rejected substitution, rollback, and revoked replay.");
} finally {
  rmSync(output, { recursive: true, force: true });
}
