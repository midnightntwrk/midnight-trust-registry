import assert from "node:assert/strict";

import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

/** Keeps proposal denial and replacement on an isolated fixture ledger. */
export function runDenialSafetyScenario(matrix, signCompact) {
  const denialHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-denial");
  const denialSecond = createMaintainerScenarioFixture("governed-demo-denial-second");
  const denialThird = createMaintainerScenarioFixture("governed-demo-denial-third");
  const deniedIssuer = createIssuerScenarioFixture("governed-demo-denied-issuer");
  const replacementIssuer = {
    ...deniedIssuer,
    authorizationId: `${deniedIssuer.authorizationId}:replacement`,
    authorizationIdCommitment: bytes32Commitment(`${deniedIssuer.authorizationId}:replacement`),
  };
  denialHarness.authorizeMaintainer(denialSecond);
  denialHarness.authorizeMaintainer(denialThird);
  denialHarness.proposeIssuer(deniedIssuer);
  matrix.expectThrown(() => denialHarness.proposeIssuer(replacementIssuer), {
    id: "denied-proposal-blocks-live-scope-reuse",
    invariant: "A second application cannot claim the same scope while a proposal remains live",
    boundary: "compact",
    messagePattern: /live authorization/iu,
    category: "duplicate-live-scope-rejected",
  });
  denialHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const denialPrepared = denialHarness.prepareIssuerDecisionAction(deniedIssuer, "archive");
  const denialActionCount = denialHarness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => denialHarness.executeIssuerDecisionWithSignatures(
    deniedIssuer, "archive", [signCompact(denialSecond, denialPrepared, denialHarness)],
  ), {
    id: "denied-proposal-requires-quorum",
    invariant: "Archiving a pending issuer proposal requires the current maintainer quorum",
    boundary: "compact",
    messagePattern: /threshold|quorum|signer|authorization/iu,
    category: "insufficient-archive-quorum",
  });
  assert.equal(denialHarness.simulator.getLedger().governanceActionCount, denialActionCount);
  const denialEventHash = denialHarness.executeIssuerDecisionWithSignatures(
    deniedIssuer, "archive", [signCompact(denialSecond, denialPrepared, denialHarness), signCompact(denialThird, denialPrepared, denialHarness)],
  );
  assert.equal(denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment).status,
    AuthorizationStatus.archived);
  const deniedBundle = denialHarness.buildIssuerHistoricalEvidence(deniedIssuer);
  assert.equal(deniedBundle.authorization?.status, "archived");
  assert.equal(deniedBundle.authorization?.authorizedAt, undefined);
  assert.equal(deniedBundle.authorization?.activeFrom, undefined);
  matrix.expectThrown(() => new TrustRegistrySimulatorClient(denialHarness.simulator)
    .verifyIssuerAuthorizationBundle(deniedBundle, {}), {
    id: "denied-proposal-is-not-trust",
    invariant: "Historical evidence for an archived proposal cannot authorize a current issuer",
    boundary: "client",
    messagePattern: /not active/iu,
    category: "archived-issuer-not-active",
  });
  const replacementProposalEventHash = denialHarness.proposeIssuer(replacementIssuer, [denialSecond]);
  assert.equal(denialHarness.simulator.getIssuerAuthorization(replacementIssuer.authorizationIdCommitment).status,
    AuthorizationStatus.proposed);
  assert.equal(denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment).status,
    AuthorizationStatus.archived);
  return { denialEventHash, deniedIssuer, deniedBundle, replacementIssuer, replacementProposalEventHash };
}
