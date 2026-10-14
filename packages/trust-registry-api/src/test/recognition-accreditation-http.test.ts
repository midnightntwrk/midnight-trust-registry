import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  sha256Hex,
  type RecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createRecognitionAccreditationVpScenarioFixture,
  bytes32Commitment,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  recognitionAccreditationSubmissionCommitment,
  recognitionAuthorityAssertionDigest,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  RECOGNITION_VP_FIXTURE_AUTHORITY_DID,
  RECOGNITION_VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { FileRecognitionAdmissionStore } from "../file-recognition-admission.js";
import type { GovernedRecognitionProposalPort, PreparedGovernedRecognitionProposal } from "../governed-recognition-proposals.js";
import { withRecognitionProposalAdmission } from "../recognition-proposal-admission.js";
import { recognitionAuthorityChallengeBindingHash } from "../recognition-authority-challenges.js";
import { createRecognitionAccreditationHttpService, type RecognitionAccreditationHttpPort } from "../recognition-accreditation-http.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

const NOW = RECOGNITION_VP_FIXTURE_TIME_MS;
const authorityDid = RECOGNITION_VP_FIXTURE_AUTHORITY_DID;
const recognitionId = "recognition:http-accreditation:v1";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

const post = (url: string, body: unknown, authorized = true) => fetch(url, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(authorized ? { "x-authority-did": authorityDid } : {}),
  },
  body: JSON.stringify(body),
});

describe("private recognition accreditation HTTP", () => {
  let server: Server | undefined;
  const directories: string[] = [];
  const pathsForStore = async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-recognition-http-"));
    directories.push(directory);
    return {
      path: join(directory, "recognition.json"),
      governancePath: join(directory, "governance-workspace.json"),
    };
  };
  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      server = undefined;
    }
    await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
  });

  it("fails closed without a trusted port and does not expose private CORS", async () => {
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "recognition-no-port" }).snapshot),
    });
    const base = await listen(server);
    const path = `${base}/v1/recognition-evidence/${recognitionId}/challenges`;
    const response = await post(path, {});
    expect(response.status).toBe(503);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    const preflight = await fetch(path, { method: "OPTIONS", headers: { origin: "https://untrusted.example" } });
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("refuses separate challenge and receipt stores that cannot commit atomically", async () => {
    const first = await pathsForStore();
    const second = await pathsForStore();
    const port: RecognitionAccreditationHttpPort = {
      challengeStore: new FileRecognitionAdmissionStore(first.path, first.governancePath),
      admissionStore: new FileRecognitionAdmissionStore(second.path, second.governancePath),
      authorizeRequest: async () => {},
      resolveCurrentContext: async () => null,
    };
    expect(() => createRecognitionAccreditationHttpService(port, () => NOW))
      .toThrow(/must be identical/u);
  });

  it("verifies signed accreditation over HTTP with governed policy and one-use challenge", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-http-accreditation");
    const maintainer = createMaintainerScenarioFixture("recognition-http-signer");
    harness.authorizeMaintainer(maintainer);
    const anchor = {
      ...RECOGNITION_VP_FIXTURE_ANCHOR,
      targetRegistryId: harness.registryId,
      policyId: harness.policyId,
      policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
    };
    harness.governRecognitionAccreditorAnchor(anchor);
    const binding = {
      targetRegistryId: harness.registryId,
      recognitionId,
      authorityDid,
      recognizedRegistryId: anchor.recognizedRegistryId,
      scopeResourceType: anchor.scopeResourceType,
      scopeResourceId: anchor.scopeResourceId,
    };
    let policyCommitment = `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`;
    const governedCommitment = policyCommitment;
    let failAtAdmissionRead = false;
    let contextReads = 0;
    let fixture: Awaited<ReturnType<typeof createRecognitionAccreditationVpScenarioFixture>> | undefined;
    const { path: admissionPath, governancePath } = await pathsForStore();
    const admissionStore = new FileRecognitionAdmissionStore(admissionPath, governancePath);
    const recognitionFixture = {
      ...createRecognitionScenarioFixture("recognition-http-accreditation"),
      recognitionId,
      recognitionIdCommitment: bytes32Commitment(recognitionId),
      recognizedAuthorityDid: authorityDid,
      recognizedAuthorityDidCommitment: bytes32Commitment(authorityDid),
      recognizedRegistryId: anchor.recognizedRegistryId,
      recognizedRegistryIdCommitment: bytes32Commitment(anchor.recognizedRegistryId),
      scopeResourceType: anchor.scopeResourceType,
      scopeResourceTypeCommitment: bytes32Commitment(anchor.scopeResourceType),
      scopeResourceId: anchor.scopeResourceId,
      scopeResourceIdCommitment: bytes32Commitment(anchor.scopeResourceId),
    };
    const proposalPort: GovernedRecognitionProposalPort = {
      governanceWorkspacePath: governancePath,
      admissionStore,
      readBinding: async () => binding,
      readCurrentGovernance: async () => ({
        governancePolicy: harness.policyRecord,
        activePolicyCommitment: `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`,
      }),
      prepare: async (currentBinding, evidenceCommitment) => {
        if (recognitionAuthorityChallengeBindingHash(currentBinding)
          !== recognitionAuthorityChallengeBindingHash(binding)) throw new Error("Recognition binding was substituted");
        return harness.prepareRecognitionProposalAction(recognitionFixture, Buffer.from(evidenceCommitment.slice(2), "hex"));
      },
      execute: async (currentBinding, evidenceCommitment, signers, signature, prepared) => {
        if (recognitionAuthorityChallengeBindingHash(currentBinding)
          !== recognitionAuthorityChallengeBindingHash(binding)) throw new Error("Recognition binding was substituted");
        const eventHash = harness.executeRecognitionProposalWithSignatures(
          recognitionFixture, signers, signature,
          { ...prepared, evidenceHash: Buffer.from(evidenceCommitment.slice(2), "hex") },
        );
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
    };
    const port: RecognitionAccreditationHttpPort = {
      challengeStore: admissionStore,
      admissionStore,
      authorizeRequest: async (_id, request) => {
        if (request.headers["x-authority-did"] !== authorityDid) throw new Error("forbidden");
      },
      resolveCurrentContext: async (id) => {
        if (id !== recognitionId || fixture === undefined) return null;
        if (failAtAdmissionRead && ++contextReads === 4) policyCommitment = sha256Hex("policy-switched-at-admission");
        return {
          binding,
          governancePolicy: harness.policyRecord,
          activePolicyCommitment: policyCommitment,
          resolver: fixture.input.resolver,
          statusSource: fixture.input.statusSource,
        };
      },
    };
    // The server supplies the current policy/status dependencies; no such fields occur in the submitted body.
    fixture = await createRecognitionAccreditationVpScenarioFixture({ anchor });
    let clockMs = NOW;
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "recognition-http-source" }).snapshot),
      clock: () => new Date(clockMs).toISOString(),
      recognitionAccreditation: port,
      governedRecognitionProposals: proposalPort,
    });
    const base = await listen(server);
    const path = `${base}/v1/recognition-evidence/${recognitionId}`;
    expect((await post(`${path}/challenges`, {}, false)).status).toBe(403);
    policyCommitment = sha256Hex("stale-policy");
    expect((await post(`${path}/challenges`, {})).status).toBe(403);
    policyCommitment = `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`;
    const issued = await post(`${path}/challenges`, {});
    expect(issued.status).toBe(201);
    const challenge = await issued.json() as { nonce: string; challengeHash: string };
    fixture = await createRecognitionAccreditationVpScenarioFixture({ anchor, nonce: challenge.nonce });
    const statement: RecognitionAuthorityAssertion = {
      version: "tr-recognition-authority-assertion-v1",
      ...binding,
      accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(fixture.input.submission),
      challengeHash: challenge.challengeHash,
      issuedAt: new Date(NOW).toISOString(),
      expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
    };
    const methodId = `${authorityDid}#assertion-1`;
    const signed = {
      statement,
      proof: {
        verificationMethodId: methodId,
        algorithm: "jubjub-schnorr",
        signature: `0x${Buffer.from(encodeJubjubSignature(signJubjubDigestFromSeed(
          fixture.authorityAssertionSeed,
          recognitionAuthorityAssertionDigest(statement, methodId),
        ))).toString("hex")}`,
      },
    };
    const body = { nonce: challenge.nonce, signed, accreditation: fixture.input.submission };
    expect((await post(`${path}/submissions`, {
      ...body,
      governancePolicy: harness.policyRecord,
    })).status).toBe(400);
    policyCommitment = sha256Hex("stale-policy");
    expect((await post(`${path}/submissions`, body)).status).toBe(403);
    policyCommitment = governedCommitment;
    failAtAdmissionRead = true;
    contextReads = 0;
    expect((await post(`${path}/submissions`, body)).status).toBe(403);
    expect(contextReads).toBe(4);
    failAtAdmissionRead = false;
    policyCommitment = governedCommitment;
    expect(await admissionStore.readAccepted(recognitionId)).toBeNull();
    const bindingHash = sha256Hex(JSON.stringify([
      "tr:recognition:authority-challenge-binding:v1",
      binding.targetRegistryId, binding.recognitionId, binding.authorityDid, binding.recognizedRegistryId,
      binding.scopeResourceType, binding.scopeResourceId,
    ]));
    expect(await admissionStore.readLive(challenge.challengeHash, bindingHash, NOW)).not.toBeNull();
    const accepted = await post(`${path}/submissions`, body);
    expect(accepted.status).toBe(200);
    expect(accepted.headers.get("access-control-allow-origin")).toBeNull();
    expect(accepted.headers.get("cache-control")).toBe("no-store");
    const result = await accepted.json() as Record<string, unknown>;
    expect(result).toMatchObject({
      recognitionId,
      evidenceCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
      receipt: {
        recognitionId,
        evidenceCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
        policyCommitment,
        anchorCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      },
    });
    expect(JSON.stringify(result)).not.toContain(authorityDid);
    const acceptedPath = `${path}/accepted`;
    expect((await fetch(acceptedPath)).status).toBe(403);
    const recovered = await fetch(acceptedPath, { headers: { "x-authority-did": authorityDid } });
    expect(recovered.status).toBe(200);
    expect(recovered.headers.get("cache-control")).toBe("no-store");
    expect(recovered.headers.get("access-control-allow-origin")).toBeNull();
    expect(await recovered.json()).toEqual(result.receipt);
    expect((await post(`${path}/submissions`, body)).status).toBe(403);
    clockMs = NOW + 1000;
    const proposalPath = `${base}/v1/governed/recognition/${recognitionId}/proposal`;
    const receipt = result.receipt as { receiptId: string; evidenceCommitment: string };
    const proposalRequest = { receiptId: receipt.receiptId, evidenceCommitment: receipt.evidenceCommitment };
    await expect(withRecognitionProposalAdmission({
      recognitionId,
      readBinding: () => proposalPort.readBinding(recognitionId),
      ...proposalRequest,
      governanceWorkspacePath: governancePath,
      admissionStore,
      readCurrentGovernance: () => proposalPort.readCurrentGovernance(),
      execute: async () => "admitted",
      clock: () => clockMs,
    })).resolves.toBe("admitted");
    const preparedResponse = await post(`${proposalPath}/prepare`, proposalRequest);
    expect(preparedResponse.status, await preparedResponse.clone().text()).toBe(200);
    const prepared = await preparedResponse.json() as PreparedGovernedRecognitionProposal;
    expect(prepared.evidenceHash).toBe(result.evidenceCommitment);
    const signature = signPolicyBoundMaintainerActionFromSeed(
      maintainer.seed,
      Buffer.from(prepared.registryId.slice(2), "hex"),
      Buffer.from(prepared.policyCommitment.slice(2), "hex"),
      Buffer.from(prepared.actionKind.slice(2), "hex"),
      Buffer.from(prepared.actionPayloadHash.slice(2), "hex"),
      BigInt(prepared.actionSequence),
    );
    const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
    const verifierSignature = harness.signRecognitionProposalEvidence(
      harness.prepareRecognitionProposalAction(recognitionFixture, Buffer.from(receipt.evidenceCommitment.slice(2), "hex")),
    );
    const submitted = await post(`${proposalPath}/submit`, {
      ...proposalRequest,
      prepared,
      signers: [{
        keyId: `0x${Buffer.from(maintainer.keyId).toString("hex")}`,
        publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
        signature: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
      }],
      evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(verifierSignature)).toString("hex")}`,
    });
    expect(submitted.status).toBe(202);
    expect(harness.simulator.getLedger().recognitionCount).toBe(1n);
    expect(`0x${Buffer.from(harness.simulator.getRecognition(recognitionFixture.recognitionIdCommitment).evidenceHash).toString("hex")}`)
      .toBe(receipt.evidenceCommitment);
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(0n);
  });
});
