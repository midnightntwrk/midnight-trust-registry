import { Buffer } from "node:buffer";

import {
  type CircuitContext,
  type CircuitResults,
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
  type JubjubPoint,
} from "@midnight-ntwrk/compact-runtime";

import {
  Contract,
  type Ledger,
  ledger,
} from "./managed/trust-registry/contract/index.js";
import {
  type TrustRegistryPrivateState,
  trustRegistryWitnesses,
} from "./witnesses.js";

export const labelToBytes32 = (label: string): Uint8Array => {
  const bytes = new Uint8Array(32);
  bytes.set(Buffer.from(label).subarray(0, 32));
  return bytes;
};

export type MaintainerFixture = {
  seed: Uint8Array;
  keyId: Uint8Array;
};

export const createMaintainerFixture = (
  label: string,
  seedByte: number,
): MaintainerFixture => ({
  seed: new Uint8Array(32).fill(seedByte),
  keyId: labelToBytes32(`maintainer:${label}`),
});

export class TrustRegistrySimulator {
  readonly contract: Contract<TrustRegistryPrivateState>;
  circuitContext: CircuitContext<TrustRegistryPrivateState>;

  constructor() {
    this.contract = new Contract<TrustRegistryPrivateState>(
      trustRegistryWitnesses,
    );
    const initialState = this.contract.initialState(
      createConstructorContext({}, "0".repeat(64)),
    );
    this.circuitContext = createCircuitContext(
      sampleContractAddress(),
      initialState.currentZswapLocalState,
      initialState.currentContractState,
      initialState.currentPrivateState,
    );
  }

  getLedger(): Ledger {
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  private executeCircuit<T>(
    circuitFn: () => CircuitResults<TrustRegistryPrivateState, T>,
  ): T {
    const result = circuitFn();
    this.circuitContext = createCircuitContext(
      sampleContractAddress(),
      result.context.currentZswapLocalState,
      result.context.currentQueryContext.state,
      result.context.currentPrivateState,
    );
    return result.result;
  }

  initializeRegistry(
    registryId: Uint8Array,
    registryDidCommitment: Uint8Array,
    governancePolicyCommitment: Uint8Array,
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    maintainerThreshold: bigint,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.initializeRegistry(
        this.circuitContext,
        registryId,
        registryDidCommitment,
        governancePolicyCommitment,
        maintainerKeyId,
        maintainerPublicKey,
        maintainerThreshold,
      ),
    );
  }

  authorizeMaintainerAction(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    actionKind: Uint8Array,
    actionPayloadHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeMaintainerAction(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        actionKind,
        actionPayloadHash,
      ),
    );
  }
}
