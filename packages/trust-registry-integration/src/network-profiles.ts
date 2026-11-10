import profilesDocument from "./network-profiles.json" with { type: "json" };
import { hasExactFieldNames } from "./exact-field-names.js";

export type TrustRegistryNetworkProfile = Readonly<{
  id: "standalone";
  networkId: "undeployed";
  kind: "self-hosted-local";
  genesisPinPolicy: "per-installation";
} | {
  id: "preview" | "preprod" | "mainnet";
  networkId: "preview" | "preprod" | "mainnet";
  kind: "public";
  genesisPinPolicy: "reviewed-network";
}>;

const PROFILE_IDS = ["standalone", "preview", "preprod", "mainnet"] as const;
export type TrustRegistryNetworkProfileId = (typeof PROFILE_IDS)[number];

export function validateNetworkProfiles(document: unknown): readonly TrustRegistryNetworkProfile[] {
  if (document === null || typeof document !== "object" || Array.isArray(document)
    || !hasExactFieldNames(document as Record<string, unknown>, ["format", "profiles"])
    || (document as { format?: unknown }).format !== "tr-network-profiles-v1"
    || !Array.isArray((document as { profiles?: unknown }).profiles)) {
    throw new Error("Invalid network profile catalog");
  }
  const values = (document as { profiles: unknown[] }).profiles;
  if (values.length !== PROFILE_IDS.length) throw new Error("Network profile catalog is incomplete");
  const profiles = values.map((value): TrustRegistryNetworkProfile => {
    if (value === null || typeof value !== "object" || Array.isArray(value)
      || !hasExactFieldNames(value as Record<string, unknown>,
        ["id", "networkId", "kind", "genesisPinPolicy"])) {
      throw new Error("Invalid network profile");
    }
    const profile = value as Record<string, unknown>;
    const local = profile.id === "standalone";
    if (!PROFILE_IDS.includes(profile.id as TrustRegistryNetworkProfileId)
      || typeof profile.networkId !== "string"
      || !/^[a-z][a-z0-9-]*$/u.test(profile.networkId)
      || profile.networkId !== (local ? "undeployed" : profile.id)
      || profile.kind !== (local ? "self-hosted-local" : "public")
      || profile.genesisPinPolicy !== (local ? "per-installation" : "reviewed-network")) {
      throw new Error("Invalid network profile identity or pin policy");
    }
    return Object.freeze({
      id: profile.id as string,
      networkId: profile.networkId,
      kind: profile.kind,
      genesisPinPolicy: profile.genesisPinPolicy,
    } as TrustRegistryNetworkProfile);
  });
  if (new Set(profiles.map((profile) => profile.id)).size !== PROFILE_IDS.length
    || new Set(profiles.map((profile) => profile.networkId)).size !== PROFILE_IDS.length
    || PROFILE_IDS.some((id) => !profiles.some((profile) => profile.id === id))) {
    throw new Error("Network profiles must have unique IDs and network IDs");
  }
  return Object.freeze(profiles);
}

export const TRUST_REGISTRY_NETWORK_PROFILES = validateNetworkProfiles(profilesDocument);

export function getNetworkProfile(id: string): TrustRegistryNetworkProfile {
  const profile = TRUST_REGISTRY_NETWORK_PROFILES.find((entry) => entry.id === id);
  if (!profile) throw new Error(`Unknown Trust Registry network profile: ${id}`);
  return profile;
}

export function getLocalNetworkProfile(): Extract<TrustRegistryNetworkProfile, { id: "standalone" }> {
  const profile = getNetworkProfile("standalone");
  if (profile.kind !== "self-hosted-local") throw new Error("Standalone profile must be local-only");
  return profile;
}
