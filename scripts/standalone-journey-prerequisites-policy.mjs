const SHA = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const NEXT_ACTION = Object.freeze({
  sourceMatchesCandidate: "Build and verify a new exact-source install; never reuse an older setup as qualification evidence.",
  setupUnlocked: "Inspect the active setup lock and its owner before resuming; do not remove it blindly.",
  installStaged: "Verify and stage the pinned install inventory and image bytes for this source revision.",
  stackObserved: "Start the dedicated local-ledger stack and observe its isolated bridge and pinned images.",
  genesisApproved: "Independently review the real chain specification, then sign the exact genesis approval with the reviewer key.",
  releaseRosterApproved: "Review and sign the release maintenance roster, threshold, public keys, custody roles, and deployment plan before deployment.",
  deploymentObserved: "Deploy through the approved provider and record finalized constructor and contract readback.",
  recordedKeyInsertionsReconciled: "Reconcile every staged verifier-key insertion against finalized deployment readback.",
  committeeApproved: "Bind the approved roster to the finalized deployment and record its separate signed approval.",
  maintenanceObserved: "Transition to the approved committee and record finalized authority and counter readback.",
});
const GATE_ORDER = Object.keys(NEXT_ACTION);

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value */
const nonzeroHash = (value) => typeof value === "string"
  && HASH.test(value) && !/^0x0{64}$/u.test(value);

/** Only checks wizard-recorded prerequisites, not an actor run or independent finality.
 * @param {unknown} status
 * @param {string | null} [expectedSourceRevision]
 */
export function assessStandaloneJourneyPrerequisites(status, expectedSourceRevision = null) {
  if (!isRecord(status) || typeof status.sourceRevision !== "string"
    || !SHA.test(status.sourceRevision) || !Array.isArray(status.stagedVerifierKeys)
    || status.releaseQualified !== false) {
    throw new Error("Invalid standalone wizard status; inspect the private setup record");
  }
  if (expectedSourceRevision !== null && !SHA.test(expectedSourceRevision)) {
    throw new Error("Expected candidate source revision must be a full lowercase commit SHA");
  }
  /** @type {Partial<Record<keyof typeof NEXT_ACTION, boolean>>} */
  const gates = {
    ...(expectedSourceRevision === null ? {} : {
      sourceMatchesCandidate: status.sourceRevision === expectedSourceRevision,
    }),
    setupUnlocked: status.setupLock === "absent",
    installStaged: status.install === "verified-staged-bytes-only",
    stackObserved: status.stackConfiguration === "observed-ledger-bridge-only",
    genesisApproved: status.localLedger === "operator-pinned-reviewer-signature-verified"
      && nonzeroHash(status.approvedGenesisHash),
    releaseRosterApproved: status.maintenanceApproval
      === "roster-signature-verified-deployment-binding-pending"
      || status.maintenanceApproval
        === "deployment-bound-roster-signature-verified-transition-pending",
    deploymentObserved: status.deployment === "observed"
      && nonzeroHash(status.deployedContractAddress),
    recordedKeyInsertionsReconciled: status.stagedVerifierKeys.length > 0
      && status.stagedVerifierKeys.every((entry) => isRecord(entry)
        && typeof entry.circuitName === "string" && entry.circuitName.length > 0
        && entry.state === "verified")
      && new Set(status.stagedVerifierKeys.map((entry) => entry.circuitName)).size
        === status.stagedVerifierKeys.length,
    committeeApproved: status.maintenanceApproval
      === "deployment-bound-roster-signature-verified-transition-pending",
    maintenanceObserved: status.maintenanceTransition === "observed"
      && status.maintenanceLastReadback === "observed"
      && status.maintenanceTransitionAlert === null,
  };
  const missing = /** @type {Array<keyof typeof NEXT_ACTION>} */ (GATE_ORDER)
    .filter((gate) => gates[gate] === false);
  const firstMissing = missing[0] ?? null;
  return {
    format: "tr-standalone-journey-prerequisites-v1",
    sourceRevision: status.sourceRevision,
    expectedSourceRevision,
    gates,
    missing,
    nextActions: missing.map((gate) => ({ gate, action: NEXT_ACTION[gate] })),
    nextSafeAction: firstMissing === null ? null : {
      gate: firstMissing, action: NEXT_ACTION[firstMissing],
    },
    blockedActions: missing.slice(1).map((gate) => ({
      gate, blockedBy: firstMissing,
    })),
    ledgerPrerequisitesObserved: missing.length === 0,
    completeVerifierKeyInventory: "not-verified",
    actorJourney: "not-run",
    signedApiPlan: "not-verified",
    egressDenied: "not-verified",
    independentFinality: "not-verified",
    releaseQualified: false,
  };
}
