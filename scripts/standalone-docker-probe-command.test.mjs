import assert from "node:assert/strict";
import { test } from "node:test";

import { requireDockerProbeSuccess } from "./standalone-docker-probe-command.mjs";

test("Docker probe result requires an actual zero exit code", () => {
  assert.equal(requireDockerProbeSuccess({ code: 0, stdout: " ready\n", stderr: "" }, "probe"), "ready");
  assert.throws(() => requireDockerProbeSuccess({ code: 7, stdout: "denied", stderr: "" }, "probe"),
    /probe failed/u);
});
