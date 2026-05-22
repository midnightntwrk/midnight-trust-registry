import { Buffer } from "node:buffer";

import {
  MidnightDIDResolver,
  MidnightNetwork,
  parseMidnightDID,
  parseMidnightDIDString,
  type MidnightLedgerState,
} from "@midnight-ntwrk/midnight-did";

type IterableWithIsEmpty<T> = Iterable<T> & {
  isEmpty(): boolean;
};

const makeIterable = <T>(items: readonly T[]): IterableWithIsEmpty<T> => ({
  [Symbol.iterator]: function* () {
    for (const item of items) {
      yield item;
    }
  },
  isEmpty: () => items.length === 0,
});

const makeIterablePairs = <K, V>(
  entries: ReadonlyArray<readonly [K, V]>,
): IterableWithIsEmpty<[K, V]> => ({
  [Symbol.iterator]: function* () {
    for (const entry of entries) {
      yield [entry[0], entry[1]];
    }
  },
  isEmpty: () => entries.length === 0,
});

const bytesFromHex = (hex: string): Uint8Array => Buffer.from(hex, "hex");

export type MidnightDidLedgerFixture = {
  did: string;
  contractAddress: string;
  network: MidnightNetwork;
  serviceEndpoint: string;
  ledgerState: MidnightLedgerState;
};

export type MidnightDidLedgerFixtureOptions = {
  serviceEndpoint?: string;
  serviceType?: string;
  verificationMethodId?: string;
  version?: bigint;
  created?: bigint;
  updated?: bigint;
};

export const createMidnightDidLedgerFixture = (
  did: string,
  options: MidnightDidLedgerFixtureOptions = {},
): MidnightDidLedgerFixture => {
  const parsedDid = parseMidnightDID(parseMidnightDIDString(did));
  if (parsedDid.network === MidnightNetwork.Offchain) {
    throw new Error(
      "Offchain Midnight DIDs are not resolved through the ledger-backed resolver fixture",
    );
  }

  const contractAddress = parsedDid.id;
  const verificationMethodId = options.verificationMethodId ?? "auth-1";
  const serviceEndpoint =
    options.serviceEndpoint ?? `https://resolver.example/${contractAddress}`;
  const version = options.version ?? 1n;
  const created = options.created ?? 1n;
  const updated = options.updated ?? 2n;

  const ledgerState = {
    id: { bytes: bytesFromHex(contractAddress) },
    version,
    active: true,
    created,
    updated,
    deactivated: false,
    operationCount: 1n,
    alsoKnownAs: makeIterable<string>([]),
    verificationMethods: makeIterablePairs<string, unknown>([
      [
        verificationMethodId,
        {
          typ: 1,
          publicKeyJwk: {
            kty: 3,
            crv: 0,
            x: 1n,
            y: 0n,
          },
        },
      ],
    ]),
    authenticationRelation: makeIterable<string>([verificationMethodId]),
    assertionMethodRelation: makeIterable<string>([]),
    keyAgreementRelation: makeIterable<string>([]),
    capabilityInvocationRelation: makeIterable<string>([]),
    capabilityDelegationRelation: makeIterable<string>([]),
    services: makeIterablePairs<string, unknown>([
      [
        "resolver",
        {
          id: "resolver",
          typ: options.serviceType ?? "LinkedDomains",
          serviceEndpoint: JSON.stringify(serviceEndpoint),
        },
      ],
    ]),
  } as MidnightLedgerState;

  return {
    did,
    contractAddress,
    network: parsedDid.network,
    serviceEndpoint,
    ledgerState,
  };
};

export const createMidnightDidResolver = (
  fixtures: readonly MidnightDidLedgerFixture[],
  expectedNetwork: MidnightNetwork | null = fixtures[0]?.network ?? null,
): MidnightDIDResolver => {
  const ledgerByContractAddress = new Map(
    fixtures.map((fixture) => [fixture.contractAddress, fixture.ledgerState]),
  );

  const ledgerReader = async (contractAddress: string) =>
    ledgerByContractAddress.get(contractAddress) ?? null;

  if (expectedNetwork === null) {
    return new MidnightDIDResolver({ ledgerReader });
  }

  return new MidnightDIDResolver({
    expectedNetwork,
    ledgerReader,
  });
};
