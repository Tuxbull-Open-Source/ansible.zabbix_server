# Variables and testing

The role identity is `tuxbull.zabbix_server`, but its public variables retain the
`zabbix_integration_*` prefix for compatibility.

## Mandatory inputs

| Variable | Accepted value |
|---|---|
| `zabbix_integration_database_password` | 20-128 characters matching `[A-Za-z0-9_-]` |
| `zabbix_integration_admin_password` | Same format |
| `zabbix_integration_server_release` | `N-releaseN.el10`, resolved for the target repositories |
| `zabbix_integration_web_release` | Same format |
| `zabbix_integration_agent_release` | Same format |

Do not copy example secrets into a deployment. Encrypt them with Ansible Vault
or supply them through an approved secret manager.

## Important defaults

| Variable | Default | Meaning |
|---|---:|---|
| `zabbix_integration_zabbix_version` | `8.0` | Supported Zabbix branch; other values are rejected |
| `zabbix_integration_postgresql_version` | `16` | Supported PostgreSQL major; other values are rejected |
| `zabbix_integration_timezone` | `UTC` | Zabbix/PHP timezone |
| `zabbix_integration_database_name` | `zabbix` | Database name |
| `zabbix_integration_database_user` | `zabbix` | Database owner |
| `zabbix_integration_server_name` | `Zabbix` | Frontend display name |
| `zabbix_integration_agent_server` | `127.0.0.1` | Required local agent server address |
| `zabbix_integration_admin_bootstrap` | `false` | Authorize initial Admin verification/rotation |
| `zabbix_integration_publish` | `false` | Enable direct self-signed HTTPS preparation |

## HTTPS publication inputs

When publication is enabled, set:

- `zabbix_integration_publish_listen_ipv4`
- `zabbix_integration_publish_server_name`

Certificate paths default below `/etc/pki/tls/zabbix-integration`. Validity
defaults to 825 days and the renewal threshold to 30 days. See
[SECURITY.md](SECURITY.md) before enabling publication.

## Resolving release suffixes

Resolve the exact Zabbix server, web, and Agent 2 package builds against the
same Rocky 10 repositories the target will use. Record only the release suffix
accepted by the role, for example `21-release1.el10`. Do not use `latest`, a
wildcard, or a value copied from an unrelated architecture or repository state.

## Controller validation

Normal check mode is intentionally unsupported by the composed upstream roles.
For input validation without mutation, set:

```yaml
zabbix_integration_validation_only: true
```

Run the repository contracts from the repository root:

```bash
python3 tests/run.py
python3 tests/schema_lifecycle/run.py
git diff --check
```

`tests/run.py` already invokes the schema lifecycle suite; the separate command
is useful for focused debugging. These tests prove controller contracts and the
executable schema/service state machine. They do not replace a fresh Rocky 10
convergence, an unchanged second convergence, reboot persistence, socket checks,
or application/API verification.
