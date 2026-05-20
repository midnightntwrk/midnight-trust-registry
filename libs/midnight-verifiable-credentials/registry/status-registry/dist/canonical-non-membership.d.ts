import { type RevocationRegistryState } from "./managed/revocation-registry/contract/index.js";
import { type BuildFreshRevokedSetNonMembershipInputsOptions, buildLiveStatusWitnessFromContractState, type BuildLiveStatusWitnessFromContractStateOptions, type BuiltFreshRevokedSetNonMembershipInputs } from "./registry-state-observation.js";
export type CanonicalNonMembershipMode = "revokedSetObservedState" | "liveContractState";
export type CanonicalObservedNonMembershipBundle = BuiltFreshRevokedSetNonMembershipInputs & {
    readonly mode: "revokedSetObservedState";
};
export type CanonicalLiveNonMembershipBundle = {
    readonly mode: "liveContractState";
    readonly registryState: RevocationRegistryState;
    readonly witness: ReturnType<typeof buildLiveStatusWitnessFromContractState>;
};
export type CanonicalNonMembershipBundle = CanonicalObservedNonMembershipBundle | CanonicalLiveNonMembershipBundle;
export type BuildCanonicalObservedNonMembershipBundleOptions = BuildFreshRevokedSetNonMembershipInputsOptions;
export type BuildCanonicalLiveNonMembershipBundleFromContractStateOptions = BuildLiveStatusWitnessFromContractStateOptions;
export declare const assertCanonicalNonMembershipBundle: (bundle: CanonicalNonMembershipBundle) => void;
export declare const buildCanonicalObservedNonMembershipBundle: (options: BuildCanonicalObservedNonMembershipBundleOptions) => CanonicalObservedNonMembershipBundle;
export declare const buildCanonicalLiveNonMembershipBundleFromContractState: ({ state, ...options }: BuildCanonicalLiveNonMembershipBundleFromContractStateOptions) => CanonicalLiveNonMembershipBundle;
//# sourceMappingURL=canonical-non-membership.d.ts.map