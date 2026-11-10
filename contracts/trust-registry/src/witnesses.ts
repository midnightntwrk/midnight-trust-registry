import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

import { type Ledger } from "./managed/trust-registry/contract/index.js";

export type TrustRegistryPrivateState = Record<string, never>;

const TWO_248 =
  452312848583266388373324160190187140051835877600158453279131187530910662656n;

export const trustRegistryWitnesses = {
  getSchnorrReduction: (
    { privateState }: WitnessContext<Ledger, TrustRegistryPrivateState>,
    challengeHash: bigint,
  ): [TrustRegistryPrivateState, [bigint, bigint]] => {
    const q = challengeHash / TWO_248;
    const r = challengeHash % TWO_248;
    return [privateState, [q, r]];
  },
};
