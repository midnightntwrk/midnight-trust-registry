import { describe, expect, it } from "vitest";

import { escapeHtml } from "../app.js";

describe("trust registry applicant portal app", () => {
  it("escapes dynamic content before rendering it into innerHTML", () => {
    expect(escapeHtml(`<degree>&"'`)).toBe(
      "&lt;degree&gt;&amp;&quot;&#39;",
    );
  });
});
