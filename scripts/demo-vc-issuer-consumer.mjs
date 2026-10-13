import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { pureCircuits } from "@midnight-ntwrk/credential-compact";
import { signMidnightDIDCredentialProof } from "@midnight-ntwrk/credential-did-midnight";
import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  deriveJubjubPublicKey,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import {
  AcceptedDecisionEpochSchema,
  DecisionEvidenceSchema,
  deriveGovernancePolicySnapshot,
  sha256Hex,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  createQuorumGatedVcAuthoritySigner,
  issuerSchemaRefFromRegistryScope,
  issueVcSignerAuthorizationFromTrustedDecision,
  pinnedVcAuthority,
  vcAuthorityDomainFields,
} from "../packages/trust-registry-integration/dist/index.js";

const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fixtureProof = (seed, authority, root, decisionSequence) => {
  const secret = seedBytesToJubjubSecretScalar(seed);
  let nonce = 0n;
  while (nonce === 0n) nonce = seedBytesToJubjubSecretScalar(randomBytes(32));
  const unsigned = {
    signerVerificationMethodRef: authority.verificationMethodRef,
    createdAt: decisionSequence,
    challengeHash: randomBytes(32),
    publicKey: deriveJubjubPublicKey(secret),
    signature: { r: deriveJubjubPublicKey(nonce), s: 0n },
  };
  return {
    ...unsigned,
    signature: {
      r: unsigned.signature.r,
      s: normalizeScalar(nonce + pureCircuits.signerAuthorizationProofChallenge(root, unsigned) * secret),
    },
  };
};

/** Simulator-only bridge from accepted HTTP evidence to the published VC consumer. */
export async function verifyGovernedIssuerCredential(input) {
  const { harness, issuer, apiBundle, applicantVp, authorityAnchor, authoritySeed, authorityKeyIdCommitment } = input;
  assert.equal(applicantVp.input.expectedSubjectDid, issuer.subjectDid);
  const bundle = harness.evaluateCurrentIssuerDecision(issuer);
  assert.equal(bundle.epoch.epochId, apiBundle.epoch.epochId);
  assert.equal(bundle.epoch.stateRoot, apiBundle.epoch.stateRoot);
  assert.ok(bundle.authorization && bundle.statusPolicyBinding);
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
  const subjectResolution = await applicantVp.input.resolver.resolveResult(issuer.subjectDid);
  assert.ok(subjectResolution);
  const stateVersion = subjectResolution.didDocumentMetadata.versionId;
  assert.equal(typeof stateVersion, "string");
  const methodId = `${issuer.subjectDid}#assertion-1`;
  const method = subjectResolution.didDocument.verificationMethod?.find((entry) => entry.id === methodId);
  assert.ok(method);
  assert.ok(subjectResolution.didDocument.assertionMethod?.includes(methodId));
  const grant = bundle.authorization;
  const evidence = DecisionEvidenceSchema.parse({
    format: "tr-decision-evidence-v1",
    role: "issuer",
    registry: { registryId: harness.registryId, registryDid: harness.registryDid, networkId, contractAddress },
    anchorReferences: {
      registryEpoch: { networkId, contractAddress, transactionHash: epochTransaction, blockHash: epochBlock },
      didState: { networkId, blockHash: didBlock },
    },
    epoch: {
      epochId: bundle.epoch.epochId,
      registryId: bundle.epoch.registryId,
      stateRoot: bundle.epoch.stateRoot,
      eventRoot: bundle.epoch.eventRoot,
      policyRoot: bundle.epoch.policyRoot,
      publicationPolicyCommitment: acceptedEpoch.publicationPolicyCommitment,
      publicationSequence: acceptedEpoch.publicationSequence,
      validFromSequence: acceptedEpoch.validFromSequence,
      validUntilSequence: acceptedEpoch.validUntilSequence,
      validFrom: bundle.epoch.validFrom,
      validUntil: bundle.epoch.validUntil,
      quorum: { requiredSignatures: acceptedEpoch.requiredSignatures, signatures: witness.signatures },
    },
    grant,
    scope: issuer.authorizationScope,
    statusPolicyBinding: bundle.statusPolicyBinding,
    didMethod: {
      did: issuer.subjectDid,
      methodId,
      methodType: "JsonWebKey",
      controller: issuer.subjectDid,
      publicKeyJwk: method.publicKeyJwk,
      relationship: "assertionMethod",
      stateVersion,
      stateEvidence: { evidenceType: "ledger-observation", blockHash: didBlock, transactionHash: didTransaction },
    },
    policy: deriveGovernancePolicySnapshot(bundle.policy),
    inclusionProof: { ...bundle.inclusionProof, leafIndex: String(bundle.inclusionProof.leafIndex) },
    governanceEvents: {
      grantTransition: grant.lifecycleEventRoot,
      quorumApproval: sha256Hex("simulator:governed-demo:approval-lookup"),
      epochPublication: witness.eventHash,
      policySnapshot: bundle.epoch.policyRoot,
    },
    decisionSequence: epochRecord.publishedAtSequence.toString(),
  });
  const currentGrant = harness.simulator.getCurrentIssuerAuthorization(
    issuer.subjectDidCommitment, issuer.resourceType, issuer.resourceIdCommitment,
  );
  const selection = {
    registryId: harness.registryId,
    networkId,
    contractAddress,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    resourceType: grant.resourceType,
    resourceId: issuer.resourceId,
    scope: issuer.authorizationScope,
  };
  const decisionPoint = {
    sequence: epochRecord.publishedAtSequence.toString(),
    evaluationTime: bundle.epoch.validFrom,
    currentPolicy: {
      root: hex(ledger.governancePolicyCommitment),
      observedAtSequence: epochRecord.publishedAtSequence.toString(),
    },
    currentGrant: {
      authorizationId: grant.authorizationId,
      lifecycleEventRoot: hex(currentGrant.lifecycleEventHash),
      status: "active",
      observedAtSequence: epochRecord.publishedAtSequence.toString(),
    },
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
  const readers = {
    readCurrentFinalizedRegistryDecision: async () => ({
      acceptedEpoch,
      publication: {
        registryIdCommitment: harness.registryIdCommitment,
        epochIdCommitment: bytes32Commitment(bundle.epoch.epochId),
        firstSignerKeyIdCommitment: epochRecord.maintainerKeyId,
        activeMaintainersAtPublication: witness.signatures.map((signer) => {
          const keyIdCommitment = bytes32Commitment(signer.keyId);
          const maintainer = ledger.maintainerRecords.lookup(keyIdCommitment);
          return { keyId: signer.keyId, keyIdCommitment, publicKey: maintainer.publicKey };
        }),
      },
      decisionPoint,
    }),
    readCurrentFinalizedDidState: async (did) => did === issuer.subjectDid
      ? subjectDidState
      : did === authorityAnchor.domain.authorityDid ? authorityDidState : null,
  };
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
    method: applicantVp.subjectAssertion.method,
    pinnedAnchor: authorityAnchor,
    authorityKeyIdCommitment,
    authorityKeyReader,
    sign: async ({ decisionRoot, decisionSequence, authority }) => fixtureProof(
      authoritySeed, authority, decisionRoot, decisionSequence,
    ),
  });
  const signed = await issueVcSignerAuthorizationFromTrustedDecision({
    evidence,
    selection,
    readers,
    method: applicantVp.subjectAssertion.method,
    anchor: authorityAnchor,
    signer,
  });
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
    const compiled = await import(pathToFileURL(join(output, "contract/index.js")).href);
    const consumer = new compiled.Contract({});
    const initial = consumer.initialState(
      createConstructorContext({}, "0".repeat(64)),
      pinnedVcAuthority(authorityAnchor),
      vcAuthorityDomainFields(authorityAnchor.domain),
    );
    const consumerContractAddress = authorityAnchor.domain.consumerContractAddress.slice(2);
    let circuitContext = createCircuitContext(
      consumerContractAddress,
      initial.currentZswapLocalState,
      initial.currentContractState,
      initial.currentPrivateState,
    );
    const installed = consumer.circuits.installSignerAuthorization(
      circuitContext, signed.descriptor, signed.proof,
    );
    circuitContext = createCircuitContext(
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
      authorizationId: hex(signed.descriptor.authorizationId),
      decisionSequence: signed.descriptor.decisionSequence.toString(),
      policyCommitment: hex(signed.descriptor.policyCommitment),
      schemaScopeCommitment: hex(signed.descriptor.scopeCommitment),
      credentialBodyRoot: hex(credentialBodyRoot),
      accepted: true,
      wrongSchemaRejected: true,
      forgedSignatureRejected: true,
      scope: "schema-level issuer proof; definition and status require separate governed checks",
    };
  } finally {
    await rm(output, { recursive: true, force: true });
  }
}
