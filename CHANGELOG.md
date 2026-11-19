# Changelog

Template history below is retained under its original attribution.

## Unreleased

### Changed

- Publish the role as `tuxbull.zabbix_server` from repository
  `ansible.zabbix_server` while retaining the `zabbix_integration_*` variable API.
- Replace the implementation-heavy README with a short operator guide, a
  runnable basic example, and linked technical documentation.

## [0.1.0] - 2026-11-18

### Added

- Add a Rocky Linux 10-only, fail-closed PostgreSQL 16 and Zabbix 8.0
  integration wrapper around pinned collection roles.
- Add controller-only contract, syntax, and installed-role validation tests.
- Record artifact hashes, upstream release identities, and unresolved live gates.
- Add a scoped community.zabbix 4.3.0 EL10 SELinux workaround with pinned policy
  ownership, repository/signature verification, and unconditional fact restoration.
- Add opt-in direct self-signed HTTPS publication after verified Admin bootstrap,
  with exact IPv4 binding, certificate validation, and no firewall mutation.
- Harden direct HTTPS with v2 ownership/publication markers, fail-closed and
  interruption-recoverable staged validation plus individually atomic file
  installs, transition teardown before package work, canonical path and regular-file
  enforcement, exact CN/SAN/self-signature checks, local-address enforcement, and
  post-reload nginx-owner, SNI fingerprint, and proxy-disabled HTTPS verification.
- Reject symlinked, non-directory, non-root-owned, or writable TLS publication
  directory chains before creation and before publication material mutations.

### Fixed

- Correct the publication variable used by marked frontend idempotence detection
  and execute its complete Jinja expression against valid and invalid published states.
- Compare strictly validated lifecycle markers by their one-line content so the
  real trailing newline does not force TLS regeneration on an unchanged rerun.

## [1.5.1] - 2026-11-04

### Changed

- Align Galaxy metadata, smoke tests, documentation, and maintainer guidance
  with the `tuxbull` namespace and Tuxbull-Open-Source workflow.
- Add the repository-versioned `skills/ansible-role-template/SKILL.md`.
- Establish `tasks/main.yml` and `tasks/include-file.yml` as the protected
  dispatcher core: update them only through a reviewed template PR, then align
  derived roles from the merged template.
- Rewrite adoption and maintenance documentation around task placement,
  shadowing, installed-role validation, and the dispatcher migration path.

### Compatibility

- Dispatcher runtime behavior is unchanged: one static implementation is
  selected for each numbered basename through the existing OS/version fallback
  order.

## [1.5.0] - 2026-10-27

Published release notes:

- Expanded supported controller role-discovery paths.
- Rewrote and aligned documentation for current operating systems.
- Began agent-assisted documentation work.

## [1.4] - 2025-01-26

Published release notes:

- Removed the `ansible_python_interpreter` handling for EL 6–8 after their
  Python support reached end of life.

## [1.3] - 2024-09-17

Published release notes:

- Added dynamic `task_dir` variables to support role nesting.

## [1.2] - 2023-05-17

Published release notes:

- Fixed `ansible.cfg` handling for Rocky Linux 9.

## [1.1] - 2022-10-18

Published release notes:

- Added the RHEL-clone distribution grouping that later evolved into the
  `rhelAll` task-dispatch family.

## [1.0] - 2022-03-20

First published release.

Published compatibility notes:

- Tested with Ansible 2.11 and AWX 18.0.
