import { describe, expect, it, vi } from "vitest";

import type { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";

import { TrustRegistrySimulatorClient } from "../simulator-client.js";

describe("async simulator client", () => {
  it("awaits the ledger format check before reading a record", async () => {
    const id = new Uint8Array(32);
    const record = { status: 1n };
    const read = vi.fn(async () => record);
    const simulator = {
      getLedger: vi.fn(async () => ({ contractVersion: 1n })),
      getIssuerAuthorization: read,
    } as unknown as TrustRegistrySimulator;
    const client = new TrustRegistrySimulatorClient(simulator);

    expect(await client.getIssuerAuthorizationById(id)).toBe(record);
    expect(simulator.getLedger).toHaveBeenCalledOnce();
    expect(read).toHaveBeenCalledWith(id);
  });

  it("does not read records from an unsupported ledger format", async () => {
    const read = vi.fn();
    const simulator = {
      getLedger: vi.fn(async () => ({ contractVersion: 2n })),
      getIssuerAuthorization: read,
    } as unknown as TrustRegistrySimulator;
    const client = new TrustRegistrySimulatorClient(simulator);

    await expect(client.getIssuerAuthorizationById(new Uint8Array(32)))
      .rejects.toThrow("Unsupported trust registry format");
    expect(read).not.toHaveBeenCalled();
  });
});
