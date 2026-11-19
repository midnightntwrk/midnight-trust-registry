import { EventEmitter } from "node:events";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";
import { actorAuthenticationDigestBytes } from "@midnightntwrk/trust-registry-domain";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loadPlan: vi.fn(),
  createSource: vi.fn(),
  createServer: vi.fn(),
}));

vi.mock("../local-ledger-runtime.js", () => ({
  assertLocalApiImageSourceRevision: vi.fn(),
  loadApprovedLocalLedgerRuntimePlanWithDigest: mocks.loadPlan,
  createApprovedLocalLedgerRuntimeSource: mocks.createSource,
}));
vi.mock("../server.js", () => ({ createTrustRegistryApiServer: mocks.createServer }));

import { runTrustRegistryApiCli } from "../cli.js";

const genesisHash = `0x${"a".repeat(64)}`;
const contractAddress = `0x${"b".repeat(64)}`;
const args = ["serve", "--local-ledger-plan", "/run/api-plan.json",
  "--local-ledger-signature", "/run/api-plan.sig",
  "--local-ledger-keyring", "/run/keyring",
  "--local-ledger-reviewer", "A".repeat(40),
  "--local-offchain-auth-store", "/run/private/challenges.json",
  "--port", "4501"];

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  mocks.loadPlan.mockResolvedValue({
    plan: { expectedGenesisHash: genesisHash, contractAddress, sourceRevision: "c".repeat(40) },
    planSha256: "d".repeat(64),
  });
  mocks.createSource.mockResolvedValue({
    loadSnapshot: vi.fn().mockResolvedValue({ registry: { registryId: "registry:live" } }),
    readFinalizedProposalLedger: vi.fn(),
  });
  mocks.createServer.mockImplementation(() => {
    const server = new EventEmitter() as EventEmitter & {
      listen: (port: number, host: string) => void;
      close: (callback?: (error?: Error) => void) => void;
    };
    server.listen = () => {
      queueMicrotask(() => server.emit("listening"));
      setTimeout(() => server.emit("close"), 0);
    };
    server.close = (callback) => { callback?.(); server.emit("close"); };
    return server;
  });
});

afterEach(() => vi.restoreAllMocks());

describe("local-ledger off-chain DID sign-in wiring", () => {
  it("uses the approved chain binding and never enables fixture mutations", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tr-local-actor-auth-"));
    try {
      const storePath = join(directory, "challenges.json");
      await runTrustRegistryApiCli(args.map((value) => value === "/run/private/challenges.json" ? storePath : value));
      const serverInput = mocks.createServer.mock.calls[0]?.[0];
      expect(serverInput).toMatchObject({
        localPlanSha256: "d".repeat(64),
        actorAuthentication: { challenges: { origin: "http://127.0.0.1:4501" } },
      });
      expect(serverInput.allowUnsafeDemoMutations).toBeUndefined();
      const authentication = serverInput.actorAuthentication.challenges;
      await expect(authentication.issue(`did:midnight:undeployed:${"e".repeat(64)}`,
        "key-1", "applicant-session")).rejects.toMatchObject({ name: "InvalidActorAuthenticationIdentityError" });

      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const publicJwk = publicKey.export({ format: "jwk" });
      const actorDid = createLongFormOffchainMidnightDIDString({
        version: 1, alsoKnownAs: [], service: [], verificationMethod: [{
          id: "#auth-1",
          publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x! },
          relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
            capabilityInvocation: false, capabilityDelegation: false },
        }],
      });
      const actorKeyId = `${actorDid}#auth-1`;
      const challenge = await authentication.issue(actorDid, actorKeyId, "applicant-session");
      expect(challenge).toMatchObject({ registryId: "registry:live", genesisHash, contractAddress,
        origin: "http://127.0.0.1:4501" });
      const signature = { keyId: actorKeyId, algorithm: "ed25519",
        value: `0x${sign(null, actorAuthenticationDigestBytes(challenge), privateKey).toString("hex")}` };
      expect(await authentication.verify(challenge, signature, "applicant-session"))
        .toEqual({ actorDid, actorKeyId });
      expect(await authentication.verify(challenge, signature, "applicant-session")).toBeNull();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
