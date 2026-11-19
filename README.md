# tuxbull.zabbix_server

[![Role tests](https://github.com/Tuxbull-Open-Source/ansible.zabbix_server/actions/workflows/tests.yml/badge.svg)](https://github.com/Tuxbull-Open-Source/ansible.zabbix_server/actions/workflows/tests.yml)

Installs a fail-closed Zabbix 8.0 server with PostgreSQL 16, the Zabbix web
frontend, and a local Zabbix Agent 2 on SELinux-enforcing Rocky Linux 10. The
role composes pinned upstream roles and keeps the existing
`zabbix_integration_*` variable API for compatibility.

## Which role do I need?

| Need | Role |
|---|---|
| Zabbix server, database, web frontend, and local agent | `tuxbull.zabbix_server` (this role) |
| Enrol a separate monitored host | `tuxbull.zabbix_agent` |

## Requirements

- Ansible Core 2.15 or newer
- Rocky Linux 10 target with SELinux enabled and enforcing
- Privilege escalation to root
- PostgreSQL 16 and Zabbix 8.0, as pinned by this role
- Access from the target to the configured Rocky, EPEL, and Zabbix repositories
- The exact collections in [`requirements.yml`](requirements.yml)

The three Zabbix package release suffixes must be resolved for the target's
Rocky 10 repositories before deployment.

## Installation

Add the role and its collections to your control project's `requirements.yml`:

```yaml
---
roles:
  - name: tuxbull.zabbix_server
    src: https://github.com/Tuxbull-Open-Source/ansible.zabbix_server.git
    scm: git

collections:
  - name: community.zabbix
    version: 4.3.0
  - name: fedora.linux_system_roles
    version: 2.5.0
```

For the complete transitive collection lock, copy this repository's
[`requirements.yml`](requirements.yml), then install both files:

```bash
ansible-galaxy role install -r requirements.yml
ansible-galaxy collection install -r requirements.yml
```

## Required variables

Store secrets with Ansible Vault or an approved secret manager.

| Variable | Requirement |
|---|---|
| `zabbix_integration_database_password` | 20-128 characters from `A-Z`, `a-z`, `0-9`, `_`, `-` |
| `zabbix_integration_admin_password` | Same format; used only when Admin bootstrap is explicitly enabled |
| `zabbix_integration_server_release` | Zabbix server release suffix such as `21-release1.el10` |
| `zabbix_integration_web_release` | Zabbix web release suffix in the same format |
| `zabbix_integration_agent_release` | Zabbix agent release suffix in the same format |

See [`docs/VARIABLES.md`](docs/VARIABLES.md) for defaults, publication inputs,
and package-resolution guidance.

## Minimal playbook

```yaml
---
- name: Install the Zabbix server
  hosts: zabbix_servers
  become: true
  roles:
    - role: tuxbull.zabbix_server
  vars:
    zabbix_integration_database_password: "{{ vault_zabbix_database_password }}"
    zabbix_integration_admin_password: "{{ vault_zabbix_admin_password }}"
    zabbix_integration_server_release: 21-release1.el10
    zabbix_integration_web_release: 21-release1.el10
    zabbix_integration_agent_release: 21-release1.el10
```

A complete sanitized project is in [`examples/basic/`](examples/basic/).

## Run and verify

From `examples/basic/`, create and encrypt the vault file, install dependencies,
check syntax, deploy, and prove an unchanged rerun:

```bash
cp vault.example.yml vault.yml
$EDITOR vault.yml
ansible-vault encrypt vault.yml
ansible-galaxy role install -r requirements.yml
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass --syntax-check
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
```

The second deployment must finish with `failed=0` and `changed=0`. Then verify
the services and exact local listeners:

```bash
ansible zabbix_servers -i inventory.yml -b --ask-vault-pass \
  -m ansible.builtin.command -a 'systemctl is-active postgresql zabbix-server nginx php-fpm zabbix-agent2'
ansible zabbix_servers -i inventory.yml -b --ask-vault-pass \
  -m ansible.builtin.shell -a "ss -H -lntp | grep -E '127\\.0\\.0\\.1:(8080|10050|10051)'"
```

## Scope and limitations

- Supports only Rocky Linux 10 with SELinux enforcing.
- Does not manage disks, LVM, filesystems, mounts, DNS, external CAs, backups,
  firewall rules, or remote-agent enrolment.
- The automation frontend is loopback-only by default. Direct self-signed HTTPS
  publication is explicit opt-in and still does not open a firewall.
- Normal Ansible check mode is rejected. Use
  `zabbix_integration_validation_only=true` for controller-side input validation.
- Package versions and repository artifacts are intentionally pinned; upgrades
  require a new audit rather than a floating version change.

## Further documentation

- [Security model](docs/SECURITY.md)
- [Architecture and implementation](docs/ARCHITECTURE.md)
- [Variables and testing](docs/VARIABLES.md)
- [Release and reuse audit](docs/REUSE-AUDIT.md)
- [Controller test coverage](tests/CONTROLLER-TESTS.md)

## Project status

This is an independent community role and is not affiliated with or supported by
Zabbix LLC. Development was AI-assisted under maintainer review. Trust should be
based on the pinned dependencies, documented security boundaries, tests, and
your own environment validation.
