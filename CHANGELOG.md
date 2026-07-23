# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- upgraded vendored `midnight-did` dependencies consumed by trust-registry from
  `0.4.0` to the published `0.5.0-rc1` tarballs
- aligned the repo with the pnpm `10.34.1` baseline used by the current DID
  repository

### Added

- public-repo hardening with PR-title/body validation and a quality workflow
- root demo commands for preparing a seeded operator workspace and booting the
  API, admin console, and applicant portal from the repo root
- issue-backed backlog tracking for the next 20 trust-registry implementation
  slices
