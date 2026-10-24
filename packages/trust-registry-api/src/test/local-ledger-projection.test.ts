import { execFileSync } from "node:child_process";
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
  assertCompletePolicyRevisionHistory,
  assertLocalLedgerEvidenceMatchesSnapshot,
  assertLocalLedgerProjectionMatchesSnapshot,
} from "../local-ledger-projection.js";
import { createLocalLedgerBoundSource } from "../local-ledger-source.js";
import { createTrustRegistryApiServer } from "../server.js";
import {
  CurrentLedgerSelectionAmbiguousError,
  CurrentLedgerSelectionUnavailableError,
  resolveAuthorizationEntry,
  resolveRecognitionEntry,
  type TrustRegistryApiStateSource,
} from "../source.js";

const sequenceToTimestamp = (sequence: bigint): string =>
  new Date(Date.parse("2026-05-20T00:00:00Z") + Number(sequence) * 60_000).toISOString();

const revisionMap = <K, V>(entries: [K, V][], keyOf: (key: K) => string) => {
  const values = new Map(entries.map(([key, value]) => [keyOf(key), value]));
  return {
    isEmpty: () => values.size === 0,
    size: () => BigInt(values.size),
    member: (key: K) => values.has(keyOf(key)),
    lookup: (key: K): V => {
      const value = values.get(keyOf(key));
      if (value === undefined) throw new Error("Missing policy revision fixture key");
      return value;
    },
    [Symbol.iterator]: () => entries[Symbol.iterator](),
  };
};

const policyHistory = (versions: [bigint, Uint8Array, bigint][]) => ({
  governancePolicyVersion: 3n,
  governanceActionCount: 5n,
  governancePolicyCommitmentsByVersion: revisionMap(
    versions.map(([version, commitment]) => [version, commitment]), String),
  governancePolicyVersionsByCommitment: revisionMap(
    versions.map(([version, commitment]) => [commitment, version]),
    (key: Uint8Array) => Buffer.from(key).toString("hex")),
  governancePolicyEffectiveFromByVersion: revisionMap(
    versions.map(([version, , effectiveFrom]) => [version, effectiveFrom]), String),
});

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
  it("resolves local current records by finalized selection, not lifecycle timestamps", async () => {
    const { snapshot } = fixture();
    const currentIssuer = snapshot.issuerEntries[1]!;
    const olderIssuer = { ...snapshot.issuerEntries[0]!, authorization: {
      ...snapshot.issuerEntries[0]!.authorization,
      subjectDid: currentIssuer.authorization.subjectDid,
      resourceId: currentIssuer.authorization.resourceId,
      resourceType: currentIssuer.authorization.resourceType,
      effectiveUntil: "2099-01-01T00:00:00.000Z",
    } };
    const currentRecognition = snapshot.recognitionEntries[0]!;
    const olderRecognition = { ...currentRecognition, recognition: {
      ...currentRecognition.recognition,
      recognitionId: "older-recognition",
      effectiveUntil: "2099-01-01T00:00:00.000Z",
    } };
    const candidate = { ...snapshot,
      issuerEntries: [olderIssuer, currentIssuer],
      recognitionEntries: [olderRecognition, currentRecognition],
    };
    const selection = {
      snapshot: candidate,
      authorizationIds: { issuer: new Set([currentIssuer.authorization.authorizationId]),
        verifier: new Set<string>(), auditor: new Set<string>() },
      recognitionIds: new Set([currentRecognition.recognition.recognitionId]),
    };
    const source: TrustRegistryApiStateSource = { mode: "local-ledger",
      async loadSnapshot() { return candidate; },
      async loadCurrentLedgerSelection() { return selection; },
    };
    const issuerRequest = { role: "issuer" as const,
      subjectDid: currentIssuer.authorization.subjectDid,
      resourceId: currentIssuer.authorization.resourceId,
    };
    const recognitionRequest = {
      recognizedAuthorityDid: currentRecognition.recognition.recognizedAuthorityDid,
      scopeResourceId: currentRecognition.recognition.scope.resourceId,
    };
    expect(await resolveAuthorizationEntry(source, issuerRequest)).toEqual(currentIssuer);
    expect(await resolveRecognitionEntry(source, recognitionRequest)).toEqual(currentRecognition);
    await expect(resolveAuthorizationEntry({ mode: "local-ledger", async loadSnapshot() {
      return candidate;
    } }, issuerRequest)).rejects.toBeInstanceOf(CurrentLedgerSelectionUnavailableError);
    const ambiguous: TrustRegistryApiStateSource = { ...source,
      async loadCurrentLedgerSelection() { return { ...selection, authorizationIds: {
        ...selection.authorizationIds,
        issuer: new Set([olderIssuer.authorization.authorizationId,
          currentIssuer.authorization.authorizationId]),
      } }; },
    };
    await expect(resolveAuthorizationEntry(ambiguous, issuerRequest))
      .rejects.toBeInstanceOf(CurrentLedgerSelectionAmbiguousError);
    const server = createTrustRegistryApiServer({ source: ambiguous });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Expected local HTTP listener");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/authorizations/resolve`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(issuerRequest),
      });
      expect(response.status).toBe(409);
      expect((await response.json()).type).toMatch(/ambiguous-current-scope$/u);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) =>
        error ? reject(error) : resolve()));
    }
  });

  it("requires a contiguous and ordered policy revision history", () => {
    const first = new Uint8Array(32).fill(1);
    const second = new Uint8Array(32).fill(2);
    const third = new Uint8Array(32).fill(3);
    const valid = policyHistory([[1n, first, 0n], [2n, second, 2n], [3n, third, 4n]]);
    expect(() => assertCompletePolicyRevisionHistory(valid)).not.toThrow();
    expect(() => assertCompletePolicyRevisionHistory(policyHistory([
      [1n, first, 0n], [3n, third, 4n], [4n, second, 5n],
    ]))).toThrow(/incomplete/u);
    expect(() => assertCompletePolicyRevisionHistory(policyHistory([
      [1n, first, 0n], [2n, second, 2n], [3n, third, 2n],
    ]))).toThrow(/inconsistent/u);
    expect(() => assertCompletePolicyRevisionHistory(policyHistory([
      [1n, first, 0n], [2n, second, 2n], [3n, third, 6n],
    ]))).toThrow(/inconsistent/u);
    expect(() => assertCompletePolicyRevisionHistory({ ...valid,
      governancePolicyVersionsByCommitment: revisionMap([
        [first, 1n], [second, 3n], [third, 2n],
      ], (key: Uint8Array) => Buffer.from(key).toString("hex")),
    })).toThrow(/inconsistent/u);
  });

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

  it("rejects missing and redirected current-scope index entries", () => {
    const { snapshot, ledger } = fixture();
    const emptyIndex = revisionMap<Uint8Array, Uint8Array>([], (key) => Buffer.from(key).toString("hex"));
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger,
      currentIssuerAuthorizationIdsByScopeKey: emptyIndex,
    } as typeof ledger)).toThrow(/issuer finalized current-scope index is incomplete/u);
    const verifierIndex = [...ledger.currentVerifierAuthorizationIdsByScopeKey];
    const redirectedIndex = revisionMap<Uint8Array, Uint8Array>(
      verifierIndex.map(([key]) => [key, new Uint8Array(32)]),
      (key) => Buffer.from(key).toString("hex"),
    );
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger,
      currentVerifierAuthorizationIdsByScopeKey: redirectedIndex,
    } as typeof ledger)).toThrow(/verifier finalized current-scope index differs/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger,
      currentAuditorAuthorizationIdsByScopeKey: emptyIndex,
    } as typeof ledger)).toThrow(/auditor finalized current-scope index is incomplete/u);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger,
      currentRecognitionIdsByScopeKey: emptyIndex,
    } as typeof ledger)).toThrow(/recognition finalized current-scope index is incomplete/u);
  });

  it("rejects stale total and active counters for every current record map", () => {
    const { snapshot, ledger } = fixture();
    for (const [label, field] of [
      ["issuer", "issuerAuthorizationCount"],
      ["verifier", "verifierAuthorizationCount"],
      ["auditor", "auditorAuthorizationCount"],
      ["recognition", "recognitionCount"],
    ] as const) {
      expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
        ...ledger, [field]: ledger[field] + 1n,
      })).toThrow(new RegExp(`${label} finalized counters differ`, "u"));
    }
    for (const [label, field] of [
      ["issuer", "activeIssuerAuthorizationCount"],
      ["verifier", "activeVerifierAuthorizationCount"],
      ["auditor", "activeAuditorAuthorizationCount"],
      ["recognition", "activeRecognitionCount"],
    ] as const) {
      expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
        ...ledger, [field]: ledger[field] + 1n,
      })).toThrow(new RegExp(`${label} finalized counters differ`, "u"));
    }
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, epochCommitmentCount: ledger.epochCommitmentCount + 1n,
    })).toThrow(/Epoch finalized counter differs/u);
  });

  it("rejects inconsistent current lifecycle sequences", () => {
    const { snapshot, ledger } = fixture();
    const keyOf = (key: Uint8Array) => Buffer.from(key).toString("hex");
    const issuerRecords = revisionMap(
      [...ledger.issuerAuthorizationRecords].map(([key, record], index) => [key,
        index === 0 ? { ...record, lastStatusSequence: 0n } : record] as [Uint8Array, typeof record]), keyOf);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, issuerAuthorizationRecords: issuerRecords,
    } as typeof ledger)).toThrow(/issuer finalized last status sequence differs/u);
    const verifierRecords = revisionMap(
      [...ledger.verifierAuthorizationRecords].map(([key, record]) => [key,
        { ...record, activeFromSequence: ledger.governanceActionCount + 1n }] as [Uint8Array, typeof record]), keyOf);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, verifierAuthorizationRecords: verifierRecords,
    } as typeof ledger)).toThrow(/verifier finalized lifecycle sequences are inconsistent/u);
    const auditorRecords = revisionMap(
      [...ledger.auditorAuthorizationRecords].map(([key, record]) => [key,
        { ...record, activeFromSequence: 0n }] as [Uint8Array, typeof record]), keyOf);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, auditorAuthorizationRecords: auditorRecords,
    } as typeof ledger)).toThrow(/auditor finalized lifecycle status disagrees/u);
    const recognitionRecords = revisionMap(
      [...ledger.recognitionRecords].map(([key, record]) => [key,
        { ...record, authorizedAtSequence: record.effectiveFromSequence + 1n }] as [Uint8Array, typeof record]), keyOf);
    expect(() => assertLocalLedgerProjectionMatchesSnapshot(snapshot, {
      ...ledger, recognitionRecords,
    } as typeof ledger)).toThrow(/recognition finalized lifecycle sequences are inconsistent/u);
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
  it("rejects a FIFO snapshot without waiting for a writer", async () => {
    const { ledger, contractAddress } = fixture();
    const directory = await mkdtemp(join(tmpdir(), "tr-local-fifo-snapshot-"));
    try {
      const snapshotPath = join(directory, "snapshot-fifo");
      execFileSync("mkfifo", [snapshotPath]);
      const address = `0x${Buffer.from(contractAddress).toString("hex")}`;
      const source = createLocalLedgerBoundSource({
        snapshotPath,
        expectedSnapshotSha256: "a".repeat(64),
        contractAddress: address,
        reader: { async readCurrentFinalizedLedger() {
          return { networkId: "undeployed", contractAddress: address,
            finalizedBlockHash: `0x${"b".repeat(64)}`, ledger,
            verifierKeySha256: {}, maintenanceAuthority: { committee: [], threshold: 0, counter: 0n } };
        } },
        sequenceToTimestamp,
      });
      await expect(source.loadSnapshot()).rejects.toMatchObject({
        cause: { message: expect.stringMatching(/bounded regular file/u) },
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("bounds a stalled finalized reader and refuses further reads until restart", async () => {
    const { contractAddress } = fixture();
    let readerCalls = 0;
    let resolveLate: (value: null) => void = () => {};
    const stalled = new Promise<null>((resolve) => { resolveLate = resolve; });
    const source = createLocalLedgerBoundSource({
      snapshotPath: "/unused/when-reader-stalls",
      expectedSnapshotSha256: "a".repeat(64),
      contractAddress: `0x${Buffer.from(contractAddress).toString("hex")}`,
      reader: { readCurrentFinalizedLedger() { readerCalls += 1; return stalled; } },
      sequenceToTimestamp,
      readTimeoutMs: 25,
    });
    const reads = await Promise.allSettled([
      source.loadSnapshot(), source.readFinalizedProposalLedger(),
    ]);
    expect(reads.map((result) => result.status)).toEqual(["rejected", "rejected"]);
    expect(readerCalls).toBe(1);
    await expect(source.loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
    resolveLate(null);
    await expect(source.readFinalizedProposalLedger()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
    expect(readerCalls).toBe(1);

    const server = createTrustRegistryApiServer({ source });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const bound = server.address();
      if (bound === null || typeof bound === "string") throw new Error("Expected local HTTP listener");
      const response = await fetch(`http://127.0.0.1:${bound.port}/v1/registry`);
      expect(response.status).toBe(503);
      expect((await response.json()).title).toBe("local ledger unavailable");
    } finally {
      if (server.listening) {
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      }
    }
  });

  it("exposes proposal readback only from the same snapshot-bound finalized view", async () => {
    const { snapshot, ledger, contractAddress } = fixture();
    const directory = await mkdtemp(join(tmpdir(), "tr-local-proposal-readback-"));
    let server: ReturnType<typeof createTrustRegistryApiServer> | undefined;
    try {
      const snapshotPath = join(directory, "snapshot.json");
      await writeSnapshotToFile(snapshotPath, snapshot);
      const address = `0x${Buffer.from(contractAddress).toString("hex")}`;
      let view = { networkId: "undeployed", contractAddress: address,
        finalizedBlockHash: `0x${"a".repeat(64)}`, ledger,
        verifierKeySha256: {}, maintenanceAuthority: { committee: [], threshold: 0, counter: 0n } };
      const source = createLocalLedgerBoundSource({
        snapshotPath,
        expectedSnapshotSha256: createHash("sha256").update(await readFile(snapshotPath)).digest("hex"),
        contractAddress: address,
        reader: { async readCurrentFinalizedLedger() { return view; } },
        sequenceToTimestamp,
      });
      await expect(source.readFinalizedProposalLedger()).resolves.toBe(ledger);
      const current = await source.loadCurrentLedgerSelection!();
      expect(current.authorizationIds.issuer).toEqual(new Set(snapshot.issuerEntries.map(
        (entry) => entry.authorization.authorizationId)));
      expect(current.recognitionIds).toEqual(new Set(snapshot.recognitionEntries.map(
        (entry) => entry.recognition.recognitionId)));
      server = createTrustRegistryApiServer({ source,
        readFinalizedProposalLedger: source.readFinalizedProposalLedger });
      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
      const bound = server.address();
      if (bound === null || typeof bound === "string") throw new Error("Expected local HTTP listener");
      const url = `http://127.0.0.1:${bound.port}/v1/governed/issuer/absent/proposal/evidence`;
      expect((await fetch(url)).status).toBe(404);
      view = { ...view, ledger: { ...ledger, governancePolicyCommitment: new Uint8Array(32).fill(7) } };
      await expect(source.readFinalizedProposalLedger()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      expect((await fetch(url)).status).toBe(503);
      view = { ...view, ledger, finalizedBlockHash: `0x${"0".repeat(64)}` };
      await expect(source.readFinalizedProposalLedger()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
    } finally {
      if (server?.listening) {
        await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects unjournaled governed ports before a local listener is created", () => {
    type Options = Parameters<typeof createTrustRegistryApiServer>[0];
    const source: Options["source"] = { mode: "local-ledger", async loadSnapshot() {
      throw new Error("No deployed ledger is available");
    } };
    const issuerPort: NonNullable<Options["governedIssuerProposals"]> = {
      prepare: async () => { throw new Error("unused"); },
      preflightSubmission: async () => {},
      execute: async () => { throw new Error("unused"); },
    };
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
    const sourceWithReader: Options["source"] = { ...source, readFinalizedProposalLedger: finalizedReader };
    expect(() => createTrustRegistryApiServer({ source: sourceWithReader, governedIssuerProposals: issuerPort,
      proposalSubmissionJournal: journal, proposalAdmission: admission,
      readFinalizedProposalLedger: finalizedReader }))
      .toThrow(/signed deployment binding check/u);
    const boundSource: Options["source"] = { ...sourceWithReader, localDeploymentBinding: {
      contractAddress: `0x${"a".repeat(64)}`, expectedGenesisHash: `0x${"b".repeat(64)}`,
    } };
    const boundJournal = { assertDeploymentBinding: async () => {},
      executeOnce: async () => ({ eventHash: `0x${"c".repeat(64)}` }),
      reconcile: async () => { throw new Error("unused"); },
    } as NonNullable<Options["proposalSubmissionJournal"]>;
    expect(() => createTrustRegistryApiServer({ source: boundSource,
      governedIssuerProposals: {} as NonNullable<Options["governedIssuerProposals"]>,
      proposalSubmissionJournal: boundJournal, proposalAdmission: admission,
      readFinalizedProposalLedger: finalizedReader })).toThrow(/side-effect-free submission preflight/u);
    expect(() => createTrustRegistryApiServer({ source: boundSource, governedIssuerProposals: issuerPort,
      proposalSubmissionJournal: boundJournal, proposalAdmission: admission,
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
      verifierKeySha256: {},
      maintenanceAuthority: { committee: [], threshold: 0, counter: 0n },
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
      const restartedSource = () => createLocalLedgerBoundSource({
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
      expect(healthy.headers.get("cache-control")).toBe("no-store");
      expect(await healthy.json()).toMatchObject({ status: "ok", sourceMode: "local-ledger" });
      expect(readCount).toBe(1);
      const malformedRequest = await fetch(`${url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{invalid",
      });
      expect(malformedRequest.status).toBe(400);
      expect(readCount).toBe(1);
      const issuer = snapshot.issuerEntries[0]!.authorization;
      if (issuer.activeFrom === undefined) throw new Error("Issuer fixture requires activeFrom");
      const recognition = snapshot.recognitionEntries[0]!.recognition;
      const authorizationEvaluation = { role: "issuer", subjectDid: issuer.subjectDid,
        resourceId: issuer.resourceId, at: issuer.activeFrom };
      const recognitionEvaluation = { recognizedAuthorityDid: recognition.recognizedAuthorityDid,
        scopeResourceId: recognition.scope.resourceId, at: recognition.effectiveFrom };
      const authorizationTrqp = { entity_id: issuer.subjectDid,
        authority_id: snapshot.registry.registryDid, action: "issue", resource: issuer.resourceId };
      const recognitionTrqp = { entity_id: recognition.recognizedAuthorityDid,
        authority_id: snapshot.registry.registryDid, action: recognition.scope.resourceType,
        resource: recognition.scope.resourceId };
      for (const path of [
        `/v1/epochs/resolve?at=${encodeURIComponent(issuer.activeFrom)}`,
        `/v1/epochs/${snapshot.currentEpoch.epochId}`,
      ]) {
        const response = await fetch(`${url}${path}`);
        expect(response.status, path).toBe(501);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(await response.json()).toMatchObject({ status: 501,
          type: expect.stringMatching(/historical-decisions-out-of-scope$/u) });
      }
      for (const [path, body] of [
        ["/v1/authorizations/evaluate", authorizationEvaluation],
        ["/v1/authorizations/evaluate/evidence", authorizationEvaluation],
        ["/v1/recognitions/evaluate", recognitionEvaluation],
        ["/v1/recognitions/evaluate/evidence", recognitionEvaluation],
        ["/v1/trqp/authorizations/query", authorizationTrqp],
        ["/v1/trqp/authorizations/evidence", authorizationTrqp],
        ["/v1/trqp/recognitions/query", recognitionTrqp],
        ["/v1/trqp/recognitions/evidence", recognitionTrqp],
      ] as const) {
        const response = await fetch(`${url}${path}`, { method: "POST",
          headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
        expect(response.status, path).toBe(501);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(await response.json()).toMatchObject({ status: 501,
          type: expect.stringMatching(/historical-decisions-out-of-scope$/u) });
      }
      expect(readCount).toBe(1);
      const raw = await readFile(snapshotPath, "utf8");
      await writeFile(snapshotPath, raw.replace("api-ledger-coverage", "forged-registry-label"));
      const mismatched = await fetch(`${url}/health`);
      expect(mismatched.status).toBe(503);
      expect(mismatched.headers.get("cache-control")).toBe("no-store");
      expect(await mismatched.json()).toMatchObject({
        status: 503,
        type: expect.stringMatching(/local-ledger-unavailable$/u),
      });
      await writeFile(snapshotPath, raw);
      const callsAfterMismatch = readCount;
      expect((await fetch(`${url}/health`)).status).toBe(503);
      expect(readCount).toBe(callsAfterMismatch);
      await expect(restartedSource().loadSnapshot()).resolves.toBeDefined();
      const actualPath = join(directory, "actual-snapshot.json");
      await rename(snapshotPath, actualPath);
      await symlink(actualPath, snapshotPath);
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      await rm(snapshotPath);
      await rename(actualPath, snapshotPath);
      view = { ...view, ledger: { ...ledger, governancePolicyCommitment: new Uint8Array(32).fill(7) } };
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      view = { ...view, ledger, networkId: "preprod" };
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      view = { ...view, networkId: "undeployed", finalizedBlockHash: `0x${"0".repeat(64)}` };
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      view = { ...view, finalizedBlockHash: `0x${"a".repeat(64)}`,
        contractAddress: `0x${"b".repeat(64)}` };
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      available = false;
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      readError = new Error("private provider path /run/secrets/local-ledger");
      const unavailable = await fetch(`${url}/v1/registry`);
      expect(unavailable.status).toBe(503);
      const problem = await unavailable.json();
      expect(problem).toMatchObject({ status: 503, title: "local ledger unavailable" });
      expect(problem).not.toHaveProperty("detail");
      expect(JSON.stringify(problem)).not.toContain("/run/secrets/local-ledger");
      const callsBeforeProviderFailure = readCount;
      await expect(restartedSource().loadSnapshot()).rejects.toThrow(/Finalized local Trust Registry state is unavailable/u);
      expect(readCount).toBe(callsBeforeProviderFailure + 1);
      const trqp = await fetch(`${url}/v1/trqp/authorizations/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entity_id: "did:example:issuer", authority_id: snapshot.registry.registryDid,
          action: "issue", resource: "credential-family" }),
      });
      expect(trqp.status).toBe(501);
      expect(trqp.headers.get("cache-control")).toBe("no-store");
      expect(await trqp.json()).toMatchObject({ status: 501,
        title: "historical decisions are outside the local 0.1.0 profile" });
      expect(readCount).toBe(callsBeforeProviderFailure + 1);
    } finally {
      const localServer = server;
      if (localServer !== undefined && localServer.listening) {
        await new Promise<void>((resolve, reject) => localServer.close((error) => error ? reject(error) : resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
});
