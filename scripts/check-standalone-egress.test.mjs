import assert from "node:assert/strict";
import { test } from "node:test";

import { hasDefaultRoute, validateEgressProbe } from "./check-standalone-egress.mjs";

const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
const subnet = "eth0\t000015AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0";
const defaultRoute = "eth0\t00000000\t010015AC\t0003\t0\t0\t0\t00000000\t0\t0\t0";
const controlRoute = `${header}\n${subnet}\n${defaultRoute}\n`;
const isolatedRoute = `${header}\n${subnet}\n`;

test("accepts only a reachable control and denied isolated connection", () => {
  assert.equal(hasDefaultRoute(controlRoute), true);
  assert.equal(hasDefaultRoute(isolatedRoute), false);
  assert.doesNotThrow(() => validateEgressProbe({
    controlRoute, isolatedRoute, controlCode: 0, isolatedCode: 7,
  }));
});

test("does not mistake DNS, TLS, or timeout failure for denied egress", () => {
  for (const isolatedCode of [0, 6, 28, 35, 60]) {
    assert.throws(() => validateEgressProbe({
      controlRoute, isolatedRoute, controlCode: 0, isolatedCode,
    }), /connection error/u);
  }
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute, controlCode: 7, isolatedCode: 7,
  }), /Positive-control/u);
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute: controlRoute, controlCode: 0, isolatedCode: 7,
  }), /default route/u);
  assert.throws(() => validateEgressProbe({
    controlRoute: isolatedRoute, isolatedRoute, controlCode: 0, isolatedCode: 7,
  }), /Positive-control/u);
});
