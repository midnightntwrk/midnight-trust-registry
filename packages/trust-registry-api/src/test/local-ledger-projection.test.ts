import { createHash } from "node:crypto";
import { mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  TrustRegistryOperatorSnapshotSchema,
  collectAuthorizationRecord,
  collectDistinctEpochs,
  collectRecognitionRecord,
  writeSnapshotToFile,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  LocalTrustRegistryIntegrationHarness,
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  assertLocalLedgerEvidenceMatchesSnapshot,
  assertLocalLedgerProjectionMatchesSnapshot,
} from "../local-ledger-projection.js";
import { createLocalLedgerBoundSource } from "../local-ledger-source.js";
import { createTrustRegistryApiServer } from "../server.js";

const sequenceToTimestamp = (sequence: bigint): string =>
  new Date(Date.parse("2026-05-20T00:00:00Z") + Number(sequence) * 60_000).toISOString();

const fixture = () => {
  const harness = new LocalTrustRegistryIntegrationHarness("api-ledger-coverage");
  const issuer = createIssuerScenarioFixture("coverage-issuer");
  const secondIssuer = createIssuerScenarioFixture("coverage-second-issuer");
  const verifier = createVerifierScenarioFixture("coverage-verifier");
  const auditor = createAuditorScenarioFixture("coverage-auditor");
  const recognition = createRecognitionScenarioFixture("coverage-recognition");
  harness.authorizeIssuer(issuer);
  harness.authorizeIssuer(secondIssuer);
  harness.authorizeVerifier(verifier);
  harness.authorizeAuditor(auditor);
  harness.authorizeRecognition(recognition);
  const issuerEvidence = harness.evaluateCurrentIssuerDecision(issuer);
  const secondIssuerEvidence = harness.evaluateCurrentIssuerDecision(secondIssuer);
  const verifierEvidence = harness.evaluateCurrentVerifierDecision(verifier);
  const auditorEvidence = harness.evaluateCurrentAuditorDecision(auditor);
  const recognitionEvidence = harness.evaluateCurrentRecognitionDecision(recognition);
  const epochs = collectDistinctEpochs([
    issuerEvidence, secondIssuerEvidence, verifierEvidence, auditorEvidence, recognitionEvidence,
  ]);
  const snapshot = TrustRegistryOperatorSnapshotSchema.parse({
    snapshotVersion: "1",
    generatedAt: epochs.at(-1)!.validUntil,
    registryLabel: "api-ledger-coverage",
    registry: harness.registryRecord,
    policy: harness.policyRecord,
    currentEpoch: epochs.at(-1),
    epochs,
    issuerEntries: [{ label: "issuer", authorization: collectAuthorizationRecord(issuerEvidence, "issuer"),
      evidence: issuerEvidence }, { label: "second issuer",
      authorization: collectAuthorizationRecord(secondIssuerEvidence, "issuer"),
      evidence: secondIssuerEvidence }],
    verifierEntries: [{ label: "verifier", authorization: collectAuthorizationRecord(verifierEvidence, "verifier"),
      evidence: verifierEvidence }],
    auditorEntries: [{ label: "auditor", authorization: collectAuthorizationRecord(auditorEvidence, "auditor"),
      evidence: auditorEvidence }],
    recognitionEntries: [{ label: "recognition", recognition: collectRecognitionRecord(recognitionEvidence),
      evidence: recognitionEvidence }],
    evidenceArchive: [],
    notes: [],
  });
  return { snapshot, ledger: harness.simulator.getLedger(),
    contractAddress: Uint8Array.from(Buffer.from(harness.simulator.contractAddress, "hex")) };
};

describe("finalized Compact projection coverage", () => {
  it("matches all current ledger maps and rejects omitted or forged entries", () => {
    const { snapshot, ledger } = fixture();
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, ledger)).not.toThrow();
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot, issuerEntries: [] }, ledger))
      .toThrow(/issuer candidate does not cover/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot, verifierEntries: [] }, ledger))
      .toThrow(/verifier candidate does not cover/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot, auditorEntries: [] }, ledger))
      .toThrow(/auditor candidate does not cover/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot, recognitionEntries: [] }, ledger))
      .toThrow(/recognition candidate does not cover/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      issuerEntries: [...snapshot.issuerEntries, snapshot.issuerEntries[0]!],
    }, ledger)).toThrow(/Duplicate issuer/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      issuerEntries: [{ ...snapshot.issuerEntries[0]!, authorization: {
        ...snapshot.issuerEntries[0]!.authorization, status: "revoked",
      } }, snapshot.issuerEntries[1]!],
    }, ledger)).toThrow(/issuer candidate status differs/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      recognitionEntries: [{ ...snapshot.recognitionEntries[0]!, recognition: {
        ...snapshot.recognitionEntries[0]!.recognition, scope: {
          ...snapshot.recognitionEntries[0]!.recognition.scope,
          resourceId: "tr:wrong-resource",
        },
      } }],
    }, ledger)).toThrow(/Recognition candidate record differs/u);
  });

  it("rejects stale epoch coverage and changed policy commitments", () => {
    const { snapshot, ledger } = fixture();
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      epochs: snapshot.epochs.slice(1),
    }, ledger)).toThrow(/epoch candidate does not cover/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      currentEpoch: snapshot.epochs[0]!,
    }, ledger)).toThrow(/not the finalized latest epoch/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot({ ...snapshot,
      epochs: snapshot.epochs.map((epoch, index) => index === 0
        ? { ...epoch, stateRoot: `0x${"a".repeat(64)}` as typeof epoch.stateRoot } : epoch),
    }, ledger)).toThrow(/Candidate epoch differs/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, governancePolicyCommitment: new Uint8Array(32).fill(7),
    })).toThrow(/registry or policy differs/u);
  });

  it("anchors every included bundle to the Compact epoch and publication signer", () => {
    const { snapshot, ledger, contractAddress } = fixture();
    const input = { snapshot, ledger, contractAddress,
      expectedNetworkId: "undeployed" as const, sequenceToTimestamp };
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot(input)).not.toThrow();
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      snapshot: { ...snapshot, issuerEntries: [{ ...snapshot.issuerEntries[0]!, evidence: {
        ...snapshot.issuerEntries[0]!.evidence,
        inclusionProof: { ...snapshot.issuerEntries[0]!.evidence.inclusionProof,
          leafHash: `0x${"a".repeat(64)}` },
      } }],
      },
    })).toThrow(/internally consistent snapshot proof/u);
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      snapshot: { ...snapshot, issuerEntries: [
        { ...snapshot.issuerEntries[0]!, evidence: snapshot.issuerEntries[1]!.evidence },
        { ...snapshot.issuerEntries[1]!, evidence: snapshot.issuerEntries[0]!.evidence },
      ] },
    })).toThrow(/matching statement/u);
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      snapshot: { ...snapshot, issuerEntries: [{ ...snapshot.issuerEntries[0]!,
        evidence: snapshot.verifierEntries[0]!.evidence }],
      },
    })).toThrow(/matching statement|Authorization candidate/u);
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      snapshot: { ...snapshot, epochs: snapshot.epochs.map((epoch, index) => index === 0
        ? { ...epoch, validUntil: "2027-01-01T00:00:00.000Z" } : epoch) },
    })).toThrow();
    const originalEpoch = snapshot.epochs[0]!;
    const forgedEpoch = { ...originalEpoch, validUntil: "2027-01-01T00:00:00.000Z" };
    const replaceEpoch = <T extends { epoch: typeof originalEpoch }>(evidence: T): T =>
      evidence.epoch.epochId === originalEpoch.epochId
        ? { ...evidence, epoch: forgedEpoch } : evidence;
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      snapshot: { ...snapshot,
        epochs: [forgedEpoch, ...snapshot.epochs.slice(1)],
        currentEpoch: snapshot.currentEpoch.epochId === originalEpoch.epochId
          ? forgedEpoch : snapshot.currentEpoch,
        issuerEntries: snapshot.issuerEntries.map((entry) => ({ ...entry, evidence: replaceEpoch(entry.evidence) })),
        verifierEntries: snapshot.verifierEntries.map((entry) => ({ ...entry, evidence: replaceEpoch(entry.evidence) })),
        auditorEntries: snapshot.auditorEntries.map((entry) => ({ ...entry, evidence: replaceEpoch(entry.evidence) })),
        recognitionEntries: snapshot.recognitionEntries.map((entry) => ({ ...entry, evidence: replaceEpoch(entry.evidence) })),
      },
    })).toThrow(/Epoch validUntil mismatch/u);
    expect(() => assertLocalLedgerEvidenceMatchesSnapshot({ ...input,
      contractAddress: new Uint8Array(32),
    })).toThrow(/Contract address/u);
  });
});

describe("local ledger-bound API source", () => {
  it("rejects unjournaled governed ports before a local listener is created", () => {
    type Options = Parameters<typeof createTrustRegistryApiServer>[0];
    const source: Options["source"] = { mode: "local-ledger", async loadSnapshot() {
      throw new Error("No deployed ledger is available");
    } };
    const issuerPort = {} as NonNullable<Options["governedIssuerProposals"]>;
    const recognitionPort = {} as NonNullable<Options["governedRecognitionProposals"]>;
    const journal = {} as NonNullable<Options["proposalSubmissionJournal"]>;
    const admission = {} as NonNullable<Options["proposalAdmission"]>;
    const finalizedReader = {} as NonNullable<Options["readFinalizedProposalLedger"]>;
    expect(() => createTrustRegistryApiServer({ source, allowUnsafeDemoMutations: true }))
      .toThrow(/forbids demo mutations/u);
    expect(() => createTrustRegistryApiServer({ source,
      governedMembershipActions: {} as NonNullable<Options["governedMembershipActions"]> }))
      .toThrow(/durable submission adapter/u);
    expect(() => createTrustRegistryApiServer({ source,
      governedEpochPublication: {} as NonNullable<Options["governedEpochPublication"]> }))
      .toThrow(/durable submission adapter/u);
    expect(() => createTrustRegistryApiServer({ source,
      governedPolicyActions: {} as NonNullable<Options["governedPolicyActions"]> }))
      .toThrow(/durable submission adapter/u);
    expect(() => createTrustRegistryApiServer({ source, governedIssuerProposals: issuerPort }))
      .toThrow(/durable submission and finalized observation with admission/u);
    expect(() => createTrustRegistryApiServer({ source, governedIssuerProposals: issuerPort,
      proposalSubmissionJournal: journal, proposalAdmission: admission }))
      .toThrow(/durable submission and finalized observation with admission/u);
    expect(() => createTrustRegistryApiServer({ source, governedIssuerProposals: issuerPort,
      proposalSubmissionJournal: journal, readFinalizedProposalLedger: finalizedReader }))
      .toThrow(/durable submission and finalized observation with admission/u);
    expect(() => createTrustRegistryApiServer({ source, governedRecognitionProposals: recognitionPort,
      proposalSubmissionJournal: journal, readFinalizedProposalLedger: finalizedReader }))
      .toThrow(/durable submission and finalized observation with admission/u);
    expect(() => createTrustRegistryApiServer({ source, governedIssuerProposals: issuerPort,
      proposalSubmissionJournal: journal, proposalAdmission: admission,
      readFinalizedProposalLedger: finalizedReader })).not.toThrow();
  });

  it("re-reads the finalized view for every HTTP query and fails closed", async () => {
    const { snapshot, ledger, contractAddress } = fixture();
    const directory = await mkdtemp(join(tmpdir(), "tr-local-ledger-api-"));
    const snapshotPath = join(directory, "snapshot.json");
    const address = `0x${Buffer.from(contractAddress).toString("hex")}`;
    let view = {
      networkId: "undeployed",
      contractAddress: address,
      finalizedBlockHash: `0x${"a".repeat(64)}`,
      ledger,
    };
    let readCount = 0;
    let available = true;
    let readError: Error | undefined;
    let server: ReturnType<typeof createTrustRegistryApiServer> | undefined;
    try {
      await writeSnapshotToFile(snapshotPath, snapshot);
      const expectedSnapshotSha256 = createHash("sha256").update(await readFile(snapshotPath)).digest("hex");
      const source = createLocalLedgerBoundSource({
        snapshotPath,
        expectedSnapshotSha256,
        contractAddress: address,
        reader: { async readCurrentFinalizedLedger() {
          readCount += 1;
          if (readError !== undefined) throw readError;
          return available ? view : null;
        } },
        sequenceToTimestamp,
      });
      const localServer = createTrustRegistryApiServer({ source });
      server = localServer;
      await new Promise<void>((resolve) => localServer.listen(0, "127.0.0.1", resolve));
      const bound = localServer.address();
      if (bound === null || typeof bound === "string") throw new Error("Expected local HTTP listener");
      const url = `http://127.0.0.1:${bound.port}`;
      const healthy = await fetch(`${url}/health`);
      expect(healthy.status).toBe(200);
      expect(await healthy.json()).toMatchObject({ status: "ok", sourceMode: "local-ledger" });
      expect(readCount).toBe(1);
      const malformedRequest = await fetch(`${url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{invalid",
      });
      expect(malformedRequest.status).toBe(400);
      expect(readCount).toBe(1);
      const raw = await readFile(snapshotPath, "utf8");
      await writeFile(snapshotPath, raw.replace("api-ledger-coverage", "forged-registry-label"));
      const mismatched = await fetch(`${url}/health`);
      expect(mismatched.status).toBe(503);
      expect(await mismatched.json()).toMatchObject({
        status: 503,
        type: expect.stringMatching(/local-ledger-unavailable$/u),
      });
      await writeFile(snapshotPath, raw);
      const actualPath = join(directory, "actual-snapshot.json");
      await rename(snapshotPath, actualPath);
      await symlink(actualPath, snapshotPath);
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      await rm(snapshotPath);
      await rename(actualPath, snapshotPath);
      view = { ...view, ledger: { ...ledger, governancePolicyCommitment: new Uint8Array(32).fill(7) } };
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      expect(readCount).toBe(4);
      view = { ...view, ledger, networkId: "preprod" };
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      view = { ...view, networkId: "undeployed", finalizedBlockHash: `0x${"0".repeat(64)}` };
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      view = { ...view, finalizedBlockHash: `0x${"a".repeat(64)}`,
        contractAddress: `0x${"b".repeat(64)}` };
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      available = false;
      expect((await fetch(`${url}/health`)).status).not.toBe(200);
      expect(readCount).toBe(8);
      readError = new Error("private provider path /run/secrets/local-ledger");
      const unavailable = await fetch(`${url}/v1/registry`);
      expect(unavailable.status).toBe(503);
      const problem = await unavailable.json();
      expect(problem).toMatchObject({ status: 503, title: "local ledger unavailable" });
      expect(problem).not.toHaveProperty("detail");
      expect(JSON.stringify(problem)).not.toContain("/run/secrets/local-ledger");
      expect(readCount).toBe(9);
      const trqp = await fetch(`${url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entity_id: "did:example:issuer", authority_id: snapshot.registry.registryDid,
          action: "issue", resource: "credential-family" }),
      });
      expect(trqp.status).toBe(503);
      expect(await trqp.json()).toMatchObject({ status: 503, title: "local ledger unavailable" });
      expect(readCount).toBe(10);
    } finally {
      const localServer = server;
      if (localServer !== undefined && localServer.listening) {
        await new Promise<void>((resolve, reject) => localServer.close((error) => error ? reject(error) : resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
});
