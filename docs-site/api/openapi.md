# OpenAPI specification

Download or inspect the [OpenAPI 3.1 YAML](/openapi.yaml). It is checked into the documentation site so applications can import the route inventory without scraping this guide.

The document describes HTTP shapes and common problem responses. It does **not** confer trust on an API operator or turn optional ports into features of the packaged CLI. For exact semantic validation, use the source Zod schemas and the trusted-port contracts. A client must verify any returned decision bundle against its own pinned registry and accepted ledger view.

The documentation workflow builds this site on pull requests and deploys from `develop` to GitHub Pages. Until the site has been published, the YAML remains available in the repository at `docs-site/public/openapi.yaml`.
