# Overview

<!-- Describe your changes briefly here, with some context as to why this is needed. -->

Target branch: `develop`

## Submission Checklist

<!-- Please check all the boxes that apply to your pull request. -->

- [ ] Useful pull request description
- [ ] Tests are provided (if possible)
- [ ] Local PR validation passed with `./run.sh --light`
  - If contract, client, API, or UI behavior changed, also ran `./run.sh integration`
- [ ] Key commits have useful messages
- [ ] All check jobs of the CI have succeeded
- [ ] Self-reviewed the diff
- [ ] Reviewer requested
- [ ] Update README.md file (if relevant)
- [ ] Update documentation (if relevant)
- [ ] No new todos introduced

## Trust Registry Surface Checklist

Complete this section when the PR changes any public TR surface:

- [ ] Contract circuits, generated Compact artifacts, or exported runtime surfaces are documented
- [ ] Domain, client, API, CLI, or UI behavior changes are covered by tests
- [ ] Runner, demo, or CI behavior changes update the local command documentation
- [ ] DID or VC package dependency changes were validated with `./run.sh --light` and `./run.sh integration`
- [ ] Changelog entry added for reviewer-visible behavior, packaging, or workflow changes

## Links

<!--
- Link any relevant Confluence or additional Jira tickets if need be
- If your PR closes some of the existing issues, please add links to them here.
  Mentioned issues will be automatically closed.
  Usage: "Closes #<issue number>", or "Closes (paste link of issue)"
-->
