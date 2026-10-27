import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { committeeMaintenanceUpdateSha256 } from "@midnight-ntwrk/trust-registry-integration";

import { verifyLocalApiApprovalChain } from "../local-approval-chain.js";
import { loadApprovedLocalLedgerRuntimePlan } from "../local-ledger-runtime.js";

const sha256 = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");

it("verifies signed standalone approvals and rejects substitution", async () => {
  const root = await mkdtemp("/tmp/tr-api-approval-chain-");
  const signer = join(root, "signer");
  const verifier = join(root, "verifier");
  try {
    await mkdir(signer, { mode: 0o700 });
    await mkdir(verifier, { mode: 0o700 });
    execFileSync("gpgconf", ["--homedir", signer, "--launch", "gpg-agent"]);
    execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
      "--passphrase", "", "--quick-generate-key", "Approval Reviewer <reviewer@example.test>",
      "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
    const keys = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
      "--list-secret-keys"], { encoding: "utf8" });
    const fingerprint = keys.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
    expect(fingerprint).toMatch(/^[A-F0-9]{40}$/u);
    const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint!]);
    execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
      { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
    const signed = async (document: object, name: string, signingFingerprint = fingerprint!) => {
      const path = join(root, `${name}.json`);
      const signaturePath = join(root, `${name}.sig`);
      const documentBytes = Buffer.from(`${JSON.stringify(document)}\n`);
      await writeFile(path, documentBytes);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--local-user",
        signingFingerprint, "--detach-sign",
        "--output", signaturePath, path]);
      const signatureBytes = await readFile(signaturePath);
      return { documentBase64: documentBytes.toString("base64"),
        documentSha256: sha256(documentBytes), signatureBase64: signatureBytes.toString("base64"),
        signatureSha256: sha256(signatureBytes), reviewerFingerprint: signingFingerprint };
    };
    const sourceRevision = "a".repeat(40);
    const verifierKeySha256 = { first: "1".repeat(64), second: "2".repeat(64) };
    const manifestPath = join(root, "release-manifest.json");
    const manifestBytes = Buffer.from(JSON.stringify({
      format: "tr-release-candidate-manifest-v2", sourceRevision, verifierKeySha256 }));
    const releaseManifestSha256 = sha256(manifestBytes);
    await writeFile(manifestPath, manifestBytes);
    const inventoryPath = join(root, "install-inventory.json");
    const inventoryBytes = Buffer.from(JSON.stringify({ format: "tr-standalone-install-v4",
      sourceRevision, packageManifest: "release-manifest.json",
      packageManifestSha256: releaseManifestSha256,
      apiRuntime: { manifest: "images/api.manifest.json", manifestSha256: "3".repeat(64),
        archive: "images/api.image.tar", archiveSha256: "4".repeat(64) } }));
    const installInventorySha256 = sha256(inventoryBytes);
    await writeFile(inventoryPath, inventoryBytes);
    const expectedGenesisHash = `0x${"d".repeat(64)}`;
    const contractAddress = `0x${"e".repeat(64)}`;
    const committee = Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`);
    const plan = { sourceRevision, installInventorySha256, releaseManifestSha256,
      networkId: "undeployed", rpcUrl: "http://127.0.0.1:29944",
      expectedGenesisHash, contractAddress,
      verifierKeySha256,
      maintenanceAuthority: { committee, threshold: 2, counter: "2" } };
    const genesisDocument = { format: "tr-local-genesis-approval-v1", sourceRevision,
      setupId: "setup-a", stackProject: "tr-local", installInventorySha256, networkId: "undeployed",
      pinSha256: "f".repeat(64), expectedGenesisHash, rpcUrl: "http://127.0.0.1:29944",
      reviewerFingerprint: fingerprint, reviewedReference: "reviewed-genesis-sha256",
      approvedAt: "2026-10-25T00:00:00.000Z" };
    const genesisApproval = await signed(genesisDocument, "genesis");
    const deploymentPlanSha256 = "7".repeat(64);
    const committeeApproval = await signed({ format: "tr-local-committee-approval-v2",
      sourceRevision, installInventorySha256, genesisApprovalSha256: genesisApproval.documentSha256,
      deploymentPlanSha256, providerModuleSha256: "8".repeat(64),
      networkId: "undeployed", expectedGenesisHash,
      maintenancePolicy: { mode: "committee", verifyingKeys: committee, threshold: 2 },
      custodians: committee.map((verifyingKey, index) => ({
        verifyingKey, holderRole: `holder-${index}`, custodyReference: `custody-${index}` })),
      reviewerFingerprint: fingerprint, reviewedReference: "reviewed-committee",
      approvedAt: "2026-10-25T00:01:00.000Z" }, "committee");
    const receipt = { networkId: "undeployed", contractAddress, txId: "deployment-tx",
      blockHash: `0x${"9".repeat(64)}`, blockHeight: 12 };
    const committeeDeploymentApproval = await signed({
      format: "tr-local-committee-deployment-approval-v1", sourceRevision,
      committeeApprovalSha256: committeeApproval.documentSha256, deploymentPlanSha256,
      releaseManifestSha256, expectedGenesisHash, deploymentReceipt: receipt,
      reviewerFingerprint: fingerprint, reviewedReference: "reviewed-deployment",
      approvedAt: "2026-10-25T00:02:00.000Z" }, "deployment");
    const chain = { format: "tr-local-api-approval-chain-v1", sourceRevision,
      installInventorySha256, releaseManifestSha256, networkId: "undeployed",
      expectedGenesisHash, contractAddress, genesisApproval, committeeApproval,
      committeeDeploymentApproval, maintenanceReadback: {
        committeeDeploymentApprovalSha256: committeeDeploymentApproval.documentSha256,
        updateSha256: committeeMaintenanceUpdateSha256({ contractAddress, committee,
          threshold: 2, currentCounter: 1n }), txId: "maintenance-tx",
        finalizedBlockHash: `0x${"5".repeat(64)}`, status: "observed" } };
    const verify = (candidate: object, selectedPlan = plan, reviewer = fingerprint!) =>
      verifyLocalApiApprovalChain({ chainBytes: Buffer.from(`${JSON.stringify(candidate)}\n`),
        plan: selectedPlan, keyringDirectory: verifier, governanceReviewerFingerprint: reviewer });
    await expect(verify(chain)).resolves.toBeUndefined();
    execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
      "--passphrase", "", "--quick-generate-key", "Alternate Reviewer <alternate@example.test>",
      "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
    const alternateKeys = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
      "--list-secret-keys"], { encoding: "utf8" });
    const alternateFingerprint = alternateKeys.split("\n")
      .filter((line) => line.startsWith("fpr:"))
      .map((line) => line.split(":")[9])
      .find((value) => value !== fingerprint);
    expect(alternateFingerprint).toMatch(/^[A-F0-9]{40}$/u);
    const alternatePublicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export",
      alternateFingerprint!]);
    execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
      { input: alternatePublicKey, stdio: ["pipe", "pipe", "pipe"] });
    const alternateGenesis = await signed({ ...genesisDocument,
      reviewerFingerprint: alternateFingerprint }, "alternate-genesis", alternateFingerprint);
    await expect(verify({ ...chain, genesisApproval: alternateGenesis }))
      .rejects.toThrow(/Genesis approval has no approved reviewer identity/u);
    await expect(verify({ ...chain, contractAddress: `0x${"0".repeat(64)}` }))
      .rejects.toThrow(/contractAddress/u);
    await expect(verify({ ...chain, committeeApproval: { ...committeeApproval,
      signatureBase64: genesisApproval.signatureBase64 } }))
      .rejects.toThrow(/SHA-256/u);
    await expect(verify(chain, plan, "F".repeat(40))).rejects.toThrow(/reviewer identity/u);
    await expect(verify(chain, { ...plan, maintenanceAuthority: {
      ...plan.maintenanceAuthority, counter: "1" } })).rejects.toThrow(/maintenance state/u);
    await expect(verify({ ...chain, maintenanceReadback: {
      ...chain.maintenanceReadback, status: "pending" } })).rejects.toThrow(/maintenance state/u);
    await expect(verify({ ...chain, maintenanceReadback: {
      ...chain.maintenanceReadback, updateSha256: "6".repeat(64) } }))
      .rejects.toThrow(/approved committee action/u);
    await expect(verify({ ...chain, maintenanceReadback: {
      ...chain.maintenanceReadback, txId: receipt.txId } }))
      .rejects.toThrow(/maintenance state/u);
    await expect(verify({ ...chain, committeeDeploymentApproval: {
      ...committeeDeploymentApproval, documentBase64: genesisApproval.documentBase64 } }))
      .rejects.toThrow(/SHA-256/u);
    const chainPath = join(root, "approval-chain.json");
    const chainBytes = Buffer.from(`${JSON.stringify(chain)}\n`);
    await writeFile(chainPath, chainBytes, { mode: 0o600 });
    const runtime = { ...plan, format: "tr-local-api-runtime-v3", approvalChainPath: chainPath,
      approvalChainSha256: sha256(chainBytes), installInventoryPath: inventoryPath,
      installInventorySha256: sha256(inventoryBytes), releaseManifestPath: manifestPath,
      releaseManifestSha256: sha256(manifestBytes),
      rpcUrl: "http://127.0.0.1:29944", indexerHttpUrl: "http://127.0.0.1:28088/api/v4/graphql",
      indexerWsUrl: "ws://127.0.0.1:28088/api/v4/graphql/ws", allowedHosts: ["127.0.0.1"],
      snapshotPath: join(root, "snapshot.json"), snapshotSha256: "f".repeat(64),
      sequenceTimestamps: { "0": "2026-01-01T00:00:00.000Z" },
      notBefore: new Date(Date.now() - 60_000).toISOString(),
      notAfter: new Date(Date.now() + 60_000).toISOString() };
    const runtimePath = join(root, "runtime-plan.json");
    const runtimeSignaturePath = join(root, "runtime-plan.sig");
    const signRuntime = async (value: object) => {
      await writeFile(runtimePath, `${JSON.stringify(value)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", runtimeSignaturePath, runtimePath]);
    };
    const load = () => loadApprovedLocalLedgerRuntimePlan({ planPath: runtimePath,
      signaturePath: runtimeSignaturePath, keyringDirectory: verifier,
      reviewerFingerprint: fingerprint!, requireApprovalChain: true });
    await signRuntime(runtime);
    await expect(load()).resolves.toMatchObject({ format: "tr-local-api-runtime-v3",
      contractAddress });
    const legacy = Object.fromEntries(Object.entries(runtime)
      .filter(([key]) => key !== "approvalChainPath" && key !== "approvalChainSha256"));
    await signRuntime({ ...legacy, format: "tr-local-api-runtime-v2" });
    await expect(load()).rejects.toThrow(/requires a signed v3 approval-chain plan/u);
    await signRuntime(runtime);
    await writeFile(chainPath, `${JSON.stringify({ ...chain, contractAddress: `0x${"0".repeat(64)}` })}\n`);
    await expect(load()).rejects.toThrow(/approval-chain bytes differ/u);
    await writeFile(chainPath, chainBytes);
    await signRuntime({ ...runtime, contractAddress: `0x${"a".repeat(64)}` });
    await expect(load()).rejects.toThrow(/contractAddress differs/u);
  } finally {
    try { execFileSync("gpgconf", ["--homedir", signer, "--kill", "gpg-agent"]); } catch { /* Best effort. */ }
    await rm(root, { recursive: true, force: true });
  }
}, 30_000);
