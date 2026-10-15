import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { AuthorizationState, pureCircuits } from "@midnight-ntwrk/credential-compact";
import { signMidnightDIDCredentialProof } from "@midnight-ntwrk/credential-did-midnight";
import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  deriveJubjubPublicKey,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  buildDecisionEvidenceClaim,
  bytes32Commitment,
  verifyDecisionEvidenceFromApi,
} from "../packages/trust-registry-client/dist/index.js";
import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import {
  AcceptedDecisionEpochSchema,
  sha256Hex,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  createCompactLedgerDecisionReaders,
  createQuorumGatedVcAuthoritySigner,
  issuerSchemaRefFromRegistryScope,
  issueVcSignerAuthorizationFromApi,
  issueVcSignerStatusTransitionFromTrustedDecision,
  pinnedVcAuthority,
  vcAuthorityDomainFields,
  vcScopeCommitmentFromRegistryScope,
} from "../packages/trust-registry-integration/dist/index.js";

const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const methodProof = (secret, methodRef, root, decisionSequence, challengeCircuit) => {
  let nonce = 0n;
  while (nonce === 0n) nonce = seedBytesToJubjubSecretScalar(randomBytes(32));
  const unsigned = {
    signerVerificationMethodRef: methodRef,
    createdAt: decisionSequence,
    challengeHash: randomBytes(32),
    publicKey: deriveJubjubPublicKey(secret),
    signature: { r: deriveJubjubPublicKey(nonce), s: 0n },
  };
  return {
    ...unsigned,
    signature: {
      r: unsigned.signature.r,
      s: normalizeScalar(nonce + challengeCircuit(root, unsigned) * secret),
    },
  };
};
const fixtureProof = (seed, authority, root, decisionSequence) => methodProof(
  seedBytesToJubjubSecretScalar(seed), authority.verificationMethodRef, root,
  decisionSequence, pureCircuits.signerAuthorizationProofChallenge,
);

/** Simulator-only bridge from accepted HTTP evidence to a governed VC descriptor. */
async function prepareGovernedSignerAuthorization(input) {
  const {
    harness, subject, role, scope, apiBundle, applicantVp, authorityAnchor,
    authoritySeed, authorityKeyIdCommitment, inactiveState, previous,
  } = input;
  assert.ok(role === "issuer" || role === "verifier");
  assert.equal(applicantVp.input.expectedSubjectDid, subject.subjectDid);
  const bundle = inactiveState === undefined
    ? role === "issuer" ? harness.evaluateCurrentIssuerDecision(subject) : harness.evaluateCurrentVerifierDecision(subject)
    : role === "issuer" ? harness.buildIssuerHistoricalEvidence(subject) : harness.buildVerifierHistoricalEvidence(subject);
  assert.equal(bundle.epoch.epochId, apiBundle.epoch.epochId);
  assert.equal(bundle.epoch.stateRoot, apiBundle.epoch.stateRoot);
  assert.equal(bundle.authorization?.status, inactiveState ?? "active");
  assert.ok(bundle.authorization);
  if (role === "issuer") assert.ok(bundle.statusPolicyBinding);
  const epochRecord = harness.simulator.getEpochCommitment(bytes32Commitment(bundle.epoch.epochId));
  const witness = harness.getEpochPublicationWitness(bundle.epoch.epochId);
  const ledger = harness.simulator.getLedger();
  const networkId = authorityAnchor.domain.networkId;
  const contractAddress = authorityAnchor.domain.registryContractAddress;
  const epochTransaction = sha256Hex("simulator:governed-demo:epoch-transaction");
  const epochBlock = sha256Hex("simulator:governed-demo:epoch-block");
  const didTransaction = sha256Hex("simulator:governed-demo:did-transaction");
  const didBlock = sha256Hex("simulator:governed-demo:did-block");
  const acceptedEpoch = AcceptedDecisionEpochSchema.parse({
    registryId: harness.registryId,
    registryDid: harness.registryDid,
    networkId,
    contractAddress,
    transactionHash: epochTransaction,
    blockHash: epochBlock,
    epochId: bundle.epoch.epochId,
    stateRoot: hex(epochRecord.stateRoot),
    eventRoot: hex(epochRecord.eventRoot),
    policyRoot: hex(epochRecord.policyRoot),
    publicationPolicyCommitment: hex(epochRecord.publicationPolicyCommitment),
    publicationSequence: epochRecord.publishedAtSequence.toString(),
    validFromSequence: epochRecord.validFromSequence.toString(),
    validUntilSequence: epochRecord.validUntilSequence.toString(),
    publicationEventHash: hex(epochRecord.publicationEventHash),
    validFrom: bundle.epoch.validFrom,
    validUntil: bundle.epoch.validUntil,
    requiredSignatures: Number(ledger.maintainerThreshold),
  });
  assert.equal(witness.eventHash, acceptedEpoch.publicationEventHash);
  const subjectResolution = await applicantVp.input.resolver.resolveResult(subject.subjectDid);
  assert.ok(subjectResolution);
  const stateVersion = subjectResolution.didDocumentMetadata.versionId;
  assert.equal(typeof stateVersion, "string");
  const relationship = role === "issuer" ? "assertionMethod" : "authentication";
  const methodId = `${subject.subjectDid}#${role === "issuer" ? "assertion-1" : "auth-1"}`;
  const method = subjectResolution.didDocument.verificationMethod?.find((entry) => entry.id === methodId);
  assert.ok(method);
  assert.ok(subjectResolution.didDocument[relationship]?.includes(methodId));
  const grant = bundle.authorization;
  const decisionSequence = ledger.governanceActionCount.toString();
  const buildInput = {
    bundle,
    acceptedEpoch,
    publicationSignatures: witness.signatures,
    didStateBlockHash: didBlock,
    scope,
    didMethod: {
      did: subject.subjectDid,
      methodId,
      methodType: "JsonWebKey",
      controller: subject.subjectDid,
      publicKeyJwk: method.publicKeyJwk,
      relationship,
      stateVersion,
      stateEvidence: { evidenceType: "ledger-observation", blockHash: didBlock, transactionHash: didTransaction },
    },
    governanceEvents: {
      grantTransition: grant.lifecycleEventRoot,
      quorumApproval: sha256Hex("simulator:governed-demo:approval-lookup"),
      epochPublication: witness.eventHash,
      policySnapshot: bundle.epoch.policyRoot,
    },
    decisionSequence,
  };
  const evidence = buildDecisionEvidenceClaim(buildInput);
  const readCurrentGrant = () => role === "issuer"
    ? harness.simulator.getCurrentIssuerAuthorization(
      subject.subjectDidCommitment, subject.resourceType, subject.resourceIdCommitment,
    )
    : harness.simulator.getCurrentVerifierAuthorization(
      subject.subjectDidCommitment, subject.requestResourceIdCommitment,
      subject.allowedAttributeSetCommitment, subject.allowedPredicateSetCommitment,
      subject.disclosureLevelCommitment,
    );
  const currentGrant = readCurrentGrant();
  assert.ok(currentGrant);
  assert.equal(AuthorizationStatus[currentGrant.status], inactiveState ?? "active");
  const selection = {
    registryId: harness.registryId,
    networkId,
    contractAddress,
    subjectDid: subject.subjectDid,
    role,
    resourceType: grant.resourceType,
    resourceId: role === "issuer" ? subject.resourceId : subject.scopeResourceId,
    scope,
  };
  const subjectDidState = {
    networkId,
    blockHash: didBlock,
    transactionHash: didTransaction,
    stateVersion,
    deactivated: false,
    didDocument: subjectResolution.didDocument,
  };
  const authorityResolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(authorityAnchor.domain.authorityDid, {
      verificationMethodId: "authority-1",
      schnorrJubjubPublicKey: authorityAnchor.publicKey,
    }),
  ]);
  const authorityResolution = await authorityResolver.resolveResult(authorityAnchor.domain.authorityDid);
  assert.ok(authorityResolution);
  const authorityDidState = {
    networkId,
    blockHash: sha256Hex("simulator:governed-demo:authority-did-block"),
    stateVersion: authorityResolution.didDocumentMetadata.versionId,
    deactivated: false,
    didDocument: authorityResolution.didDocument,
  };
  const readers = createCompactLedgerDecisionReaders({
    readFinalizedView: async () => ({
      ledger: harness.simulator.getLedger(),
      acceptedEpoch,
      publication: {
        registryIdCommitment: harness.registryIdCommitment,
        networkIdCommitment: ledger.deploymentNetworkIdCommitment,
        contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
        epochIdCommitment: bytes32Commitment(bundle.epoch.epochId),
        firstSignerKeyIdCommitment: epochRecord.maintainerKeyId,
        activeMaintainersAtPublication: witness.signatures.map((signer) => {
          const keyIdCommitment = bytes32Commitment(signer.keyId);
          const maintainer = ledger.maintainerRecords.lookup(keyIdCommitment);
          return { keyId: signer.keyId, keyIdCommitment, publicKey: maintainer.publicKey };
        }),
      },
      evaluationTime: bundle.epoch.validFrom,
    }),
    readFinalizedDidState: async (did) => did === subject.subjectDid
      ? subjectDidState
      : did === authorityAnchor.domain.authorityDid ? authorityDidState : null,
  });
  const authorityKeyReader = {
    readCurrentFinalizedVcAuthorityState: async () => {
      const current = harness.simulator.getLedger();
      return {
        registryIdCommitment: current.registryId,
        currentPolicyCommitment: current.governancePolicyCommitment,
        currentPolicyVersion: current.governancePolicyVersion,
        currentKey: harness.simulator.getCurrentVcAuthorityKey(
          vcAuthorityDomainFields(authorityAnchor.domain).consumerContractAddress,
        ),
      };
    },
  };
  const signer = createQuorumGatedVcAuthoritySigner({
    evidence,
    selection,
    readers,
    method: role === "issuer" ? applicantVp.subjectAssertion.method : applicantVp.subjectAuthentication.method,
    pinnedAnchor: authorityAnchor,
    authorityKeyIdCommitment,
    authorityKeyReader,
    inactiveState,
    sign: async ({ decisionRoot, decisionSequence, authority }) => fixtureProof(
      authoritySeed, authority, decisionRoot, decisionSequence,
    ),
  });
  const request = {
    evidence,
    selection,
    readers,
    method: role === "issuer" ? applicantVp.subjectAssertion.method : applicantVp.subjectAuthentication.method,
    anchor: authorityAnchor,
    signer,
  };
  if (inactiveState === undefined) {
    assert.equal(typeof input.apiBase, "string");
    assert.equal(typeof input.publishDecisionEvidence, "function");
    input.publishDecisionEvidence(role, subject.authorizationId, { buildInput, selection }, readers);
  } else {
    assert.equal(typeof input.apiBase, "string");
    await assert.rejects(
      verifyDecisionEvidenceFromApi(input.apiBase, subject.authorizationId, selection, readers),
      /mismatch|unavailable/u,
    );
  }
  const signed = inactiveState === undefined
    ? await issueVcSignerAuthorizationFromApi({
      apiBase: input.apiBase,
      authorizationId: subject.authorizationId,
      selection,
      readers,
      method: request.method,
      anchor: authorityAnchor,
      signer,
    })
    : await issueVcSignerStatusTransitionFromTrustedDecision({
      ...request, previous, state: inactiveState,
    });
  return signed;
}

let compiledConsumer;
async function loadCompiledConsumer() {
  if (compiledConsumer) return compiledConsumer;
  const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const cacheRoot = resolve(projectRoot, "node_modules/.cache");
  await mkdir(cacheRoot, { recursive: true });
  const output = await mkdtemp(join(cacheRoot, "governed-vc-consumer-"));
  try {
    const vcCompactRoot = dirname(fileURLToPath(import.meta.resolve(
      "@midnight-ntwrk/credential-compact/credentials/composable.compact",
    )));
    const compile = spawnSync(process.execPath, [
      resolve(projectRoot, "scripts/compile-compact.mjs"),
      "--skip-zk",
      "--compact-path", vcCompactRoot,
      resolve(projectRoot, "packages/trust-registry-integration/src/compact/vc-authority-consumer.compact"),
      output,
    ], { encoding: "utf8" });
    if (compile.error) throw compile.error;
    assert.equal(compile.status, 0, compile.stderr);
    compiledConsumer = await import(pathToFileURL(join(output, "contract/index.js")).href);
    return compiledConsumer;
  } finally {
    await rm(output, { recursive: true, force: true });
  }
}

async function withCompiledConsumer(authorityAnchor, execute) {
  const compiled = await loadCompiledConsumer();
  const consumer = new compiled.Contract({});
  const initial = consumer.initialState(
    createConstructorContext({}, "0".repeat(64)),
    pinnedVcAuthority(authorityAnchor),
    vcAuthorityDomainFields(authorityAnchor.domain),
  );
  const consumerContractAddress = authorityAnchor.domain.consumerContractAddress.slice(2);
  const circuitContext = createCircuitContext(
    consumerContractAddress,
    initial.currentZswapLocalState,
    initial.currentContractState,
    initial.currentPrivateState,
  );
  return execute({ compiled, consumer, circuitContext, consumerContractAddress });
}

/** End-to-end issuer VC proof after the HTTP and Compact governance path. */
export async function verifyGovernedIssuerCredential(input) {
  const { issuer, applicantVp, authorityAnchor } = input;
  const signed = await prepareGovernedSignerAuthorization({
    ...input, subject: issuer, role: "issuer", scope: issuer.authorizationScope,
  });
  return withCompiledConsumer(authorityAnchor, ({ compiled, consumer, circuitContext: initialContext, consumerContractAddress }) => {
    const installed = consumer.circuits.installSignerAuthorization(
      initialContext, signed.descriptor, signed.proof,
    );
    const circuitContext = createCircuitContext(
      consumerContractAddress,
      installed.context.currentZswapLocalState,
      installed.context.currentQueryContext.state,
      installed.context.currentPrivateState,
    );
    const credential = {
      version: 1n,
      schema: issuerSchemaRefFromRegistryScope(issuer.authorizationScope),
      issuerVerificationMethodRef: applicantVp.subjectAssertion.method.verificationMethodRef,
      holderBinding: { holderVerificationMethodRef: {
        controllerAddress: { bytes: bytes32Commitment("demo-credential-holder") },
        methodId: bytes32Commitment("demo-holder-method"),
      } },
      statusBinding: {},
      issuedAt: 1n,
      hasExpiration: false,
      expiresAt: 0n,
      claims: {},
      claimCommitments: {},
      claimRoot: bytes32Commitment("demo-credential-claim"),
    };
    const credentialBodyRoot = compiled.pureCircuits.credentialBodyRoot(credential);
    const credentialProof = signMidnightDIDCredentialProof({
      methodBinding: applicantVp.subjectAssertion.method,
      secretScalar: applicantVp.subjectAssertion.secretScalar,
      bodyRoot: credentialBodyRoot,
      createdAt: 1n,
      challengeHash: randomBytes(32),
    });
    consumer.circuits.assertIssuerCredentialSchemaSignerProof(
      circuitContext, credential, credentialProof, signed.descriptor.authorizationId,
    );
    assert.throws(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
      circuitContext,
      { ...credential, schema: { ...credential.schema, schemaId: bytes32Commitment("wrong-demo-schema") } },
      credentialProof,
      signed.descriptor.authorizationId,
    ));
    assert.throws(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
      circuitContext,
      credential,
      { ...credentialProof, signature: { ...credentialProof.signature, s: credentialProof.signature.s + 1n } },
      signed.descriptor.authorizationId,
    ));
    return {
      signedHistory: [signed],
      credential,
      credentialProof,
      report: {
        authorizationId: hex(signed.descriptor.authorizationId),
        decisionSequence: signed.descriptor.decisionSequence.toString(),
        policyCommitment: hex(signed.descriptor.policyCommitment),
        schemaScopeCommitment: hex(signed.descriptor.scopeCommitment),
        credentialBodyRoot: hex(credentialBodyRoot),
        accepted: true,
        wrongSchemaRejected: true,
        forgedSignatureRejected: true,
        scope: "schema-level issuer proof; definition and status require separate governed checks",
      },
    };
  });
}

/** Relayer fixture: replay accepted descriptors, then install a newer inactive decision. */
async function verifyGovernedStatusUpdate(input, role, subject, scope) {
  const { authorityAnchor, state, previousJourney } = input;
  assert.ok(state === "suspended" || state === "revoked");
  assert.ok(previousJourney.signedHistory.length > 0);
  const previous = previousJourney.signedHistory.at(-1).descriptor;
  const signed = await prepareGovernedSignerAuthorization({
    ...input, subject, role, scope,
    inactiveState: state, previous,
  });
  return withCompiledConsumer(authorityAnchor, ({ consumer, circuitContext: initialContext, consumerContractAddress }) => {
    let circuitContext = initialContext;
    for (const accepted of [...previousJourney.signedHistory, signed]) {
      const installed = consumer.circuits.installSignerAuthorization(
        circuitContext, accepted.descriptor, accepted.proof,
      );
      circuitContext = createCircuitContext(
        consumerContractAddress,
        installed.context.currentZswapLocalState,
        installed.context.currentQueryContext.state,
        installed.context.currentPrivateState,
      );
    }
    if (role === "issuer") {
      assert.throws(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
        circuitContext, previousJourney.credential, previousJourney.credentialProof,
        signed.descriptor.authorizationId,
      ), /must be active/u);
    } else {
      assert.throws(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, previousJourney.requestScopeCommitment, previousJourney.requestProof,
        signed.descriptor.authorizationId,
      ), /must be active/u);
    }
    assert.throws(() => consumer.circuits.installSignerAuthorization(
      circuitContext, previousJourney.signedHistory[0].descriptor,
      previousJourney.signedHistory[0].proof,
    ), /sequence must increase/u);
    if (state === "revoked") {
      const resurrected = {
        ...signed.descriptor,
        state: AuthorizationState.active,
        decisionSequence: signed.descriptor.decisionSequence + 1n,
      };
      const authority = pinnedVcAuthority(authorityAnchor);
      const resurrectionRoot = pureCircuits.signerAuthorizationDecisionRoot(
        resurrected, authority.domainCommitment,
      );
      const resurrectionProof = fixtureProof(
        input.authoritySeed, authority, resurrectionRoot, resurrected.decisionSequence,
      );
      assert.throws(() => consumer.circuits.installSignerAuthorization(
        circuitContext, resurrected, resurrectionProof,
      ), /must remain revoked/u);
    }
    return {
      ...previousJourney,
      signedHistory: [...previousJourney.signedHistory, signed],
      report: {
        status: state,
        decisionSequence: signed.descriptor.decisionSequence.toString(),
        authorizationId: hex(signed.descriptor.authorizationId),
        [role === "issuer" ? "priorCredentialProofRejected" : "priorRequestProofRejected"]: true,
        staleApiDecisionRejected: true,
        staleDescriptorReplayRejected: true,
        ...(state === "revoked" ? { resurrectionRejected: true } : {}),
      },
    };
  });
}

export const verifyGovernedIssuerStatusUpdate = (input) => verifyGovernedStatusUpdate(
  input, "issuer", input.issuer, input.issuer.authorizationScope,
);

export const verifyGovernedVerifierStatusUpdate = (input) => verifyGovernedStatusUpdate(
  input, "verifier", input.verifier, input.scope,
);

/** End-to-end verifier request proof, not a holder-presentation authorization. */
export async function verifyGovernedVerifierRequest(input) {
  const { verifier, scope, applicantVp, authorityAnchor } = input;
  const signed = await prepareGovernedSignerAuthorization({
    ...input, subject: verifier, role: "verifier", scope,
  });
  return withCompiledConsumer(authorityAnchor, ({ consumer, circuitContext: initialContext, consumerContractAddress }) => {
    const installed = consumer.circuits.installSignerAuthorization(
      initialContext, signed.descriptor, signed.proof,
    );
    const circuitContext = createCircuitContext(
      consumerContractAddress,
      installed.context.currentZswapLocalState,
      installed.context.currentQueryContext.state,
      installed.context.currentPrivateState,
    );
    const requestScopeCommitment = vcScopeCommitmentFromRegistryScope(scope);
    const requestProof = methodProof(
      applicantVp.subjectAuthentication.secretScalar,
      applicantVp.subjectAuthentication.method.verificationMethodRef,
      requestScopeCommitment,
      2n,
      pureCircuits.verifierRequestProofChallenge,
    );
    consumer.circuits.assertVerifierRequestAuthorized(
      circuitContext, requestScopeCommitment, requestProof, signed.descriptor.authorizationId,
    );
    const changedProfiles = {
      attributes: { ...scope, allowedAttributes: [...scope.allowedAttributes, "allowed-attribute-set:extra"] },
      predicates: { ...scope, allowedPredicates: [...scope.allowedPredicates, "allowed-predicate-set:extra"] },
      purpose: { ...scope, purpose: "unapproved-purpose" },
      disclosure: { ...scope, disclosureLevel: "disclosure-level:full" },
    };
    for (const changedScope of Object.values(changedProfiles)) {
      const changedCommitment = vcScopeCommitmentFromRegistryScope(changedScope);
      assert.notEqual(hex(changedCommitment), hex(requestScopeCommitment));
      const changedProof = methodProof(
        applicantVp.subjectAuthentication.secretScalar,
        applicantVp.subjectAuthentication.method.verificationMethodRef,
        changedCommitment,
        2n,
        pureCircuits.verifierRequestProofChallenge,
      );
      assert.throws(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, changedCommitment, changedProof, signed.descriptor.authorizationId,
      ), /scope does not match request/u);
    }
    assert.throws(() => consumer.circuits.assertVerifierRequestAuthorized(
      circuitContext, bytes32Commitment("wrong-verifier-request-profile"), requestProof,
      signed.descriptor.authorizationId,
    ));
    assert.throws(() => consumer.circuits.assertVerifierRequestAuthorized(
      circuitContext, requestScopeCommitment,
      { ...requestProof, signature: { ...requestProof.signature, s: requestProof.signature.s + 1n } },
      signed.descriptor.authorizationId,
    ));
    return {
      signedHistory: [signed],
      requestScopeCommitment,
      requestProof,
      report: {
        authorizationId: hex(signed.descriptor.authorizationId),
        decisionSequence: signed.descriptor.decisionSequence.toString(),
        policyCommitment: hex(signed.descriptor.policyCommitment),
        requestScopeCommitment: hex(requestScopeCommitment),
        accepted: true,
        wrongProfileRejected: true,
        rejectedProfileChanges: Object.keys(changedProfiles),
        forgedSignatureRejected: true,
        scope: "approved verifier request profile; holder VP trust is a separate decision",
      },
    };
  });
}
