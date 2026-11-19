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
export async function runDenialSafetyScenario(matrix, signCompact) {
  const denialHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-denial");
  const denialSecond = createMaintainerScenarioFixture("governed-demo-denial-second");
  const denialThird = createMaintainerScenarioFixture("governed-demo-denial-third");
  const deniedIssuer = createIssuerScenarioFixture("governed-demo-denied-issuer");
  const replacementIssuer = {
    ...deniedIssuer,
    authorizationId: `${deniedIssuer.authorizationId}:replacement`,
    authorizationIdCommitment: bytes32Commitment(`${deniedIssuer.authorizationId}:replacement`),
  };
  await denialHarness.authorizeMaintainer(denialSecond);
  await denialHarness.authorizeMaintainer(denialThird);
  await denialHarness.proposeIssuer(deniedIssuer);
  await matrix.expectRejected(() => denialHarness.proposeIssuer(replacementIssuer), {
    id: "denied-proposal-blocks-live-scope-reuse",
    invariant: "A second application cannot claim the same scope while a proposal remains live",
    boundary: "compact",
    messagePattern: /live authorization/iu,
    category: "duplicate-live-scope-rejected",
  });
  await denialHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const denialPrepared = await denialHarness.prepareIssuerDecisionAction(deniedIssuer, "archive");
  const denialActionCount = (await denialHarness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => denialHarness.executeIssuerDecisionWithSignatures(
    deniedIssuer, "archive", [await signCompact(denialSecond, denialPrepared, denialHarness)],
  ), {
    id: "denied-proposal-requires-quorum",
    invariant: "Archiving a pending issuer proposal requires the current maintainer quorum",
    boundary: "compact",
    messagePattern: /threshold|quorum|signer|authorization/iu,
    category: "insufficient-archive-quorum",
  });
  assert.equal((await denialHarness.simulator.getLedger()).governanceActionCount, denialActionCount);
  const denialEventHash = await denialHarness.executeIssuerDecisionWithSignatures(
    deniedIssuer, "archive", [await signCompact(denialSecond, denialPrepared, denialHarness), await signCompact(denialThird, denialPrepared, denialHarness)],
  );
  assert.equal((await denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment)).status,
    AuthorizationStatus.archived);
  const deniedBundle = await denialHarness.buildIssuerHistoricalEvidence(deniedIssuer);
  assert.equal(deniedBundle.authorization?.status, "archived");
  assert.equal(deniedBundle.authorization?.authorizedAt, undefined);
  assert.equal(deniedBundle.authorization?.activeFrom, undefined);
  await matrix.expectRejected(() => new TrustRegistrySimulatorClient(denialHarness.simulator)
    .verifyIssuerAuthorizationBundle(deniedBundle, {}), {
    id: "denied-proposal-is-not-trust",
    invariant: "Historical evidence for an archived proposal cannot authorize a current issuer",
    boundary: "client",
    messagePattern: /not active/iu,
    category: "archived-issuer-not-active",
  });
  const replacementProposalEventHash = await denialHarness.proposeIssuer(replacementIssuer, [denialSecond]);
  assert.equal((await denialHarness.simulator.getIssuerAuthorization(replacementIssuer.authorizationIdCommitment)).status,
    AuthorizationStatus.proposed);
  assert.equal((await denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment)).status,
    AuthorizationStatus.archived);
  return { denialEventHash, deniedIssuer, deniedBundle, replacementIssuer, replacementProposalEventHash };
}
