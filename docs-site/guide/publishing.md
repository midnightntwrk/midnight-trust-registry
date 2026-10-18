# Documentation development and publishing

The site uses VitePress like the sibling Midnight DID documentation. Source lives in `docs-site/`; normative product specifications and ADRs remain in `docs/`.

```bash
pnpm install --frozen-lockfile
pnpm run docs:dev
./run.sh docs
```

`docs:dev` serves the site locally. `./run.sh docs` runs the repository link/privacy check, validates the OpenAPI route inventory, and builds the site. `./run.sh --light` remains the general repository gate. The diagrams use Mermaid, so a browser smoke is useful when changing diagram syntax; a static VitePress build does not parse Mermaid source.

The [documentation workflow](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/.github/workflows/docs-site.yml) builds on documentation-related pull requests, including stacked PRs. A push or manual dispatch on `develop` uploads the built `docs-site/.vitepress/dist` artifact and deploys it to [GitHub Pages](https://midnightntwrk.github.io/midnight-trust-registry/). PRs never deploy. Pages is configured with **GitHub Actions** as its source, and the workflow smoke-tests the landing page, guide, model, sequence page, API page, and OpenAPI YAML after deployment.

`DOCS_BASE` overrides the base path for a different host. In GitHub Actions, the default base is derived from `GITHUB_REPOSITORY`, so project Pages links and assets use `/midnight-trust-registry/`; local development uses `/`.
