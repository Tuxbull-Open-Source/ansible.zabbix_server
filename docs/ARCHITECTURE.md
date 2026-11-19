# Architecture and implementation

`tuxbull.zabbix_server` is a thin composition role for one Rocky Linux 10
Zabbix server. It keeps the historical `zabbix_integration_*` input namespace so
existing inventories do not need a variable migration.

## Ownership boundaries

| Layer | Owner |
|---|---|
| PostgreSQL engine, initialization, local listener, authentication, service | `fedora.linux_system_roles.postgresql` |
| Zabbix database, user, schema, server package and service | pinned `community.zabbix` server role plus this role's lifecycle wrapper |
| Zabbix repository and Agent 2 packages | pinned `community.zabbix` roles |
| Narrow nginx/PHP-FPM configuration and frontend lifecycle | this role |
| Disks, filesystems, firewall, DNS, external PKI, backups | caller |

The PostgreSQL handler is flushed before readiness and schema work. Schema
management probes catalog state before import, refuses ambiguous partial state,
keeps the Zabbix service stopped and masked until verification succeeds, and
preserves unchanged stable reruns. The executable lifecycle harness drives the
production pre/post task files through stateful fake database, package, and
service boundaries.

## Execution stages

The protected dispatcher selects numbered task files for Rocky Linux 10:

1. Validate platform, secrets, pins, and publication inputs.
2. Install deterministic prerequisites and establish fail-closed service state.
3. Configure PostgreSQL and verify readiness.
4. Configure the Zabbix server and own the displaced schema/service lifecycle.
5. Configure the loopback-only web frontend.
6. Install and verify the local Agent 2 listener.
7. Optionally bootstrap the Admin credential.
8. Optionally prepare and verify direct HTTPS publication.
9. Finish with fail-closed assertions.

`tasks/main.yml` and `tasks/include-file.yml` are inherited dispatcher contracts
and must remain byte-for-byte unchanged.

## Listener model

The automation frontend binds `127.0.0.1:8080`. Direct HTTPS, when explicitly
enabled, adds only `<requested-ipv4>:443`. Agent and server sockets are checked
against their requested loopback behavior. Wildcard, unexpected IPv6, and
wrong-process listeners are rejected rather than delegated to a firewall.

## Package and collection pins

The role uses an eleven-collection transitive lock. The checksum helper verifies
published artifacts without installing them. Zabbix release suffixes are
mandatory caller inputs because they must come from a real target repository
transaction. EPEL, fping, and SELinux policy builds are fixed to audited Rocky
10 artifacts; upgrade work requires refreshing the audit and fixtures.

See [REUSE-AUDIT.md](REUSE-AUDIT.md) for artifact provenance and upstream gap
details, and [SECURITY.md](SECURITY.md) for the fail-closed lifecycle.
