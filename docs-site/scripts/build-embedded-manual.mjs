import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createMarkdownRenderer } from "vitepress";

const docsRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manualPath = resolve(docsRoot, "guide/registry-manual.md");

export async function buildEmbeddedManual(outputPath, surface) {
  const task = surface === "applicant"
    ? { label: "Choose a role", href: "./#governed-requests", pending: "./#pending-evidence", settings: "./#connection-details" }
    : surface === "admin"
      ? { label: "Open review inbox", href: "./#review-board", settings: "./#workspace-settings" }
      : undefined;
  if (task === undefined) throw new Error("Embedded Manual requires an applicant or admin surface");
  const source = await readFile(manualPath, "utf8");
  // The embedded page is offline and self-contained; don't leave links to absent chapters.
  const offlineSource = source.replaceAll(/\[([^\]]+)\]\((?:\.\.?\/)[^)]+\)/gu, "$1");
  const markdown = await createMarkdownRenderer(docsRoot, { highlight: () => "" });
  const content = markdown.render(offlineSource);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Registry Manual | Midnight Trust Registry</title>
<style>
@font-face{font-family:Outfit;src:url('./fonts/outfit-latin.woff2') format('woff2');font-weight:400 800;font-display:swap}
:root{color-scheme:light;font-family:Outfit,sans-serif;color:#19383e;background:#e9efef}
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:clamp(1rem,3vw,3rem)}
.layout{max-width:68rem;margin:auto;display:grid;grid-template-columns:14rem minmax(0,1fr);gap:1.5rem}
.rail{background:#dae5e4;border-radius:16px;padding:1.5rem;align-self:start}.rail img{width:7.4rem;filter:brightness(0);opacity:.78}
.rail strong{display:block;margin:.8rem 0 1.5rem;font-size:1.4rem}.rail nav{display:grid;gap:.8rem}.rail a{color:#275961;font-weight:700}
.rail .task-link{display:block;padding:.75rem 1rem;border-radius:9px;background:#275961;color:#fff;text-decoration:none}
main{min-width:0;padding:clamp(1.25rem,3vw,3rem);border:1px solid #c7d9d0;border-radius:18px;background:#f8faf8}
h1,h2{letter-spacing:-.035em;line-height:1.15}h1{font-size:clamp(2rem,4vw,3rem);margin-top:0}h2{margin-top:2.2rem}
p,li{line-height:1.65}a{color:#275961}a:focus-visible,.rail a:focus-visible{outline:2px solid #275961;outline-offset:3px}
.notice{padding:1rem;border:1px solid #a6c2b6;border-radius:10px;background:#e4efea;line-height:1.5}
table{display:block;overflow-x:auto;border-collapse:collapse;width:100%}th,td{padding:.7rem;border-bottom:1px solid #c7d9d0;text-align:left;vertical-align:top}th{background:#e4efea}
pre{overflow-x:auto}code{overflow-wrap:anywhere}
@media(max-width:740px){.layout{grid-template-columns:1fr}.rail{position:static}.rail strong{display:inline;margin-left:1rem}main{padding:1.25rem}}
</style></head><body><div class="layout"><aside class="rail"><img src="./midnight-logo.svg" alt="Midnight"><strong>Trust Registry</strong><nav aria-label="Continue in the app"><a class="task-link" href="${task.href}">${task.label}</a>${"pending" in task ? `<a href="${task.pending}">Continue pending request</a>` : ""}<a href="${task.settings}">Digital identity settings</a></nav></aside>
<main id="content"><p class="notice">This Manual is included for offline reading. Related chapters and the latest updates are in the separate documentation site. Phase-0 DID sign-in requires an external signer and same-origin host; it does not grant a role. VP-based eligibility is still planned.</p>${content}</main></div></body></html>`;
  await writeFile(outputPath, html, "utf8");
}
