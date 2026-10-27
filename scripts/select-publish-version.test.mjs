import assert from "node:assert/strict";
import test from "node:test";

import { selectPublishVersion } from "./select-publish-version.mjs";

test("only committed 0.1.0 release-candidate versions may enter npm publication", () => {
  assert.equal(selectPublishVersion("0.1.0-rc1"), "0.1.0-rc1");
  assert.equal(selectPublishVersion("0.1.0-rc12"), "0.1.0-rc12");
  for (const value of ["0.1.0", "0.1.0-rc0", "0.1.0-rc01", "0.1.1-rc1", "1.0.0",
    "0.1.0-rc1; echo injected", undefined]) {
    assert.throws(() => selectPublishVersion(value), /committed 0\.1\.0-rcN version/u);
  }
});
