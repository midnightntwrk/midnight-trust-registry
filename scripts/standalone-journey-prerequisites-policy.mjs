const SHA = /^[0-9a-f]{40}$/u;
const NEXT_ACTION = Object.freeze({
  sourceMatchesCandidate: "Build and verify a new exact-source install; never reuse an older setup as qualification evidence.",
  setupUnlocked: "Inspect the active setup lock and its owner before resuming; do not remove it blindly.",
  installStaged: "Verify and stage the pinned install inventory and image bytes for this source revision.",
  stackObserved: "Start the dedicated local-ledger stack and observe its isolated bridge and pinned images.",
  genesisApproved: "Independently review the real chain specification, then sign the exact genesis approval with the reviewer key.",
  deploymentObserved: "Deploy through the approved provider and record finalized constructor and contract readback.",
  recordedKeyInsertionsReconciled: "Reconcile every staged verifier-key insertion against finalized deployment readback.",
  committeeApproved: "Approve and sign the release committee roster, threshold, public keys, and custody roles.",
  maintenanceObserved: "Transition to the approved committee and record finalized authority and counter readback.",
});

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

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
    genesisApproved: status.localLedger === "operator-pinned-reviewer-signature-verified",
    deploymentObserved: status.deployment === "observed",
    recordedKeyInsertionsReconciled: status.stagedVerifierKeys.length > 0
      && status.stagedVerifierKeys.every((entry) => isRecord(entry) && entry.state === "verified"),
    committeeApproved: status.maintenanceApproval
      === "deployment-bound-roster-signature-verified-transition-pending",
    maintenanceObserved: status.maintenanceTransition === "observed"
      && status.maintenanceLastReadback === "observed"
      && status.maintenanceTransitionAlert === null,
  };
  const missing = /** @type {Array<keyof typeof NEXT_ACTION>} */ (Object.keys(NEXT_ACTION))
    .filter((gate) => gates[gate] === false);
  return {
    format: "tr-standalone-journey-prerequisites-v1",
    sourceRevision: status.sourceRevision,
    expectedSourceRevision,
    gates,
    missing,
    nextActions: missing.map((gate) => ({ gate, action: NEXT_ACTION[gate] })),
    ledgerPrerequisitesObserved: missing.length === 0,
    completeVerifierKeyInventory: "not-verified",
    actorJourney: "not-run",
    signedApiPlan: "not-verified",
    egressDenied: "not-verified",
    independentFinality: "not-verified",
    releaseQualified: false,
  };
}
