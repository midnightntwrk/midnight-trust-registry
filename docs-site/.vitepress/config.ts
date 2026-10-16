import { defineConfig } from "vitepress";

const repoName = process.env.GITHUB_REPOSITORY?.split("/")[1] ?? "midnight-trust-registry";
const base = process.env.DOCS_BASE ?? (process.env.GITHUB_ACTIONS ? `/${repoName}/` : "/");

export default defineConfig({
  base,
  title: "Midnight Trust Registry",
  description: "Governed, scoped trust decisions for Midnight issuers, verifiers, and auditors.",
  cleanUrls: true,
  lastUpdated: true,
  appearance: false,
  markdown: {
    config(md) {
      const fence = md.renderer.rules.fence?.bind(md.renderer.rules);
      md.renderer.rules.fence = (tokens, idx, options, env, self) => {
        const token = tokens[idx];
        if (token.info.trim() === "mermaid") {
          return `<MermaidBlock encoded="${encodeURIComponent(token.content)}" />`;
        }
        return fence ? fence(tokens, idx, options, env, self) : self.renderToken(tokens, idx, options);
      };
    },
  },
  themeConfig: {
    siteTitle: "Trust Registry",
    search: { provider: "local" },
    nav: [
      { text: "Start", link: "/guide/" },
      { text: "Specification", link: "/spec/" },
      { text: "Model", link: "/model/" },
      { text: "Architecture", link: "/architecture/" },
      { text: "Contract", link: "/contract/" },
      { text: "API", link: "/api/" },
      { text: "GitHub", link: "https://github.com/midnightntwrk/midnight-trust-registry" },
    ],
    sidebar: {
      "/guide/": [{ text: "Guide", items: [
        { text: "Overview", link: "/guide/" },
        { text: "Quickstart and demo", link: "/guide/quickstart" },
        { text: "Actors and use cases", link: "/guide/use-cases" },
        { text: "Status and limitations", link: "/guide/status" },
        { text: "Documentation publishing", link: "/guide/publishing" },
      ] }],
      "/spec/": [{ text: "Specification", items: [
        { text: "0.1.0 profile and sources", link: "/spec/" },
      ] }],
      "/model/": [{ text: "Specification", items: [
        { text: "Domain model", link: "/model/" },
        { text: "Governance", link: "/model/governance" },
        { text: "Evidence and time", link: "/model/evidence" },
        { text: "Recognition and interoperability", link: "/model/interoperability" },
      ] }],
      "/architecture/": [{ text: "Architecture", items: [
        { text: "Components and boundaries", link: "/architecture/" },
        { text: "Sequence diagrams", link: "/architecture/flows" },
      ] }],
      "/contract/": [{ text: "Contract", items: [
        { text: "Compact ledger and circuits", link: "/contract/" },
      ] }],
      "/api/": [{ text: "HTTP API", items: [
        { text: "Overview and safety", link: "/api/" },
        { text: "Endpoint reference", link: "/api/endpoints" },
        { text: "OpenAPI", link: "/api/openapi" },
      ] }],
    },
    socialLinks: [{ icon: "github", link: "https://github.com/midnightntwrk/midnight-trust-registry" }],
    footer: { message: "Midnight Trust Registry reference implementation", copyright: "Apache-2.0" },
  },
});
