import type {
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiApplicationTarget,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";

export type ApplicantTarget = TrustRegistryApiApplicationTarget;
export type PublicIssuerEntry =
  TrustRegistryApiAuthorizationListResponse["entries"][number];
export type PublicVerifierEntry =
  TrustRegistryApiAuthorizationListResponse["entries"][number];
export type PublicRecognitionEntry =
  TrustRegistryApiRecognitionListResponse["entries"][number];

export type InspectionCard = {
  id: string;
  label: string;
  scope: string;
  status: string;
  subject: string;
  target: ApplicantTarget;
  trustLevel: string;
};

export type PublicInspection = {
  activeIssuers: readonly PublicIssuerEntry[];
  activeRecognitions: readonly PublicRecognitionEntry[];
  activeVerifiers: readonly PublicVerifierEntry[];
  summary: TrustRegistryApiSummary;
};

export const TARGET_OPTIONS: readonly {
  description: string;
  label: string;
  value: ApplicantTarget;
}[] = [
  {
    value: "issuer",
    label: "Issuer",
    description: "Apply to issue credential families or schemas.",
  },
  {
    value: "verifier",
    label: "Verifier",
    description: "Apply to request governed presentation profiles.",
  },
  {
    value: "recognition",
    label: "Recognition",
    description: "Apply to register an external authority or registry scope.",
  },
];

export const toInspectionCards = (
  inspection: PublicInspection,
): readonly InspectionCard[] => [
  ...inspection.activeIssuers.map((entry) => ({
    id: entry.authorization.authorizationId,
    label: entry.label,
    scope: `${entry.authorization.resourceType}:${entry.authorization.resourceId}`,
    status: entry.authorization.status,
    subject: entry.authorization.subjectDid,
    target: "issuer" as const,
    trustLevel: entry.authorization.trustLevel,
  })),
  ...inspection.activeVerifiers.map((entry) => ({
    id: entry.authorization.authorizationId,
    label: entry.label,
    scope: `${entry.authorization.resourceType}:${entry.authorization.resourceId}`,
    status: entry.authorization.status,
    subject: entry.authorization.subjectDid,
    target: "verifier" as const,
    trustLevel: entry.authorization.trustLevel,
  })),
  ...inspection.activeRecognitions.map((entry) => ({
    id: entry.recognition.recognitionId,
    label: entry.label,
    scope: `${entry.recognition.scope.resourceType}:${entry.recognition.scope.resourceId}`,
    status: entry.recognition.status,
    subject: entry.recognition.recognizedAuthorityDid,
    target: "recognition" as const,
    trustLevel: entry.recognition.trustLevel,
  })),
];

export const describeSubmission = (
  result: TrustRegistryApiApplicationMutationResponse,
): string => {
  if (result.operation.operation === "publish-epoch") {
    return `Published epoch ${result.currentEpochId}.`;
  }

  if (result.recordKind === "authorization") {
    return `Submitted ${result.entry.label} as a ${result.operation.target} application (${result.entry.authorization.status}).`;
  }

  if (result.recordKind === "recognition") {
    return `Submitted ${result.entry.label} as a recognition application (${result.entry.recognition.status}).`;
  }

  return `Published epoch ${result.epoch.epochId}.`;
};
