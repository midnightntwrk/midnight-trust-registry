# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- upgraded the published `midnight-did` package chain and contract Schnorr
  helper from `0.5.0-rc1` to `0.5.0-rc2`
- added protected, develop-only npm publishing with local artifact and
  published-package smoke validation
- upgraded published `midnight-did` dependencies consumed by trust-registry from
  `0.4.0` to the `0.5.0-rc2` package baseline
- aligned the repo with the pnpm `10.34.1` baseline used by the current DID
  repository
- pinned repository workflows, added Scorecard coverage, and aligned Dependabot
  grouping and cooldown policy with the public `midnight-did` repository
- added pi.dev project settings and public contribution, security, and release
  policy checks

### Added

- public-repo hardening with PR-title/body validation and a quality workflow
- root demo commands for preparing a seeded operator workspace and booting the
  API, admin console, and applicant portal from the repo root
- issue-backed backlog tracking for the next 20 trust-registry implementation
  slices
