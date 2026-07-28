# Overview

<!-- Describe your changes briefly here, with some context as to why this is needed. -->

Target branch: usually `develop`; release-promotion PRs target `main`.

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
- [ ] Every commit is DCO signed and GPG signed

## Public Repository Checklist

- [ ] No secrets, private notes, local paths, wallet state, or proof-server logs were added
- [ ] Workflow and dependency changes use pinned action references where practical
- [ ] Security-sensitive changes include the relevant security boundary and test evidence
- [ ] Release, package, or documentation policy changes are reflected in public docs

## Links

<!-- Link relevant issues and supporting documentation here. -->
