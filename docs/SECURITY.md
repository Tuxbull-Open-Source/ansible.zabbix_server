# Security model

The role defaults to a closed deployment. It requires SELinux enforcing,
configures PostgreSQL for local access, binds the automation web frontend to
`127.0.0.1:8080`, and does not add firewall rules.

## Secret handling and Admin bootstrap

`zabbix_integration_database_password` and
`zabbix_integration_admin_password` must contain 20-128 URL-safe characters.
Secret-bearing tasks disable logging and diffs. Keep these values in Ansible
Vault or an approved external secret manager.

Admin bootstrap is disabled unless
`zabbix_integration_admin_bootstrap: true`. When enabled, the role first tries
the desired credential. It uses the vendor default only for the initial
transition, rotates through the documented API, reauthenticates, and verifies
the returned identity. A protected completion marker records successful
verification but never replaces reauthentication on later runs. Loopback API
requests explicitly bypass environment proxies.

## Fail-closed frontend lifecycle

The pinned upstream frontend template would create wildcard IPv4 and IPv6
listeners. This role therefore owns the narrow nginx and PHP-FPM configuration.
On initial deployment nginx remains stopped and masked through package and
configuration work, starts only after `nginx -t`, and must own only the expected
listeners. Later runs revalidate configuration, marker state, package drift,
and sockets before retaining the running service.

## Optional direct HTTPS

Direct self-signed HTTPS requires all of the following:

```yaml
zabbix_integration_admin_bootstrap: true
zabbix_integration_publish: true
zabbix_integration_publish_listen_ipv4: 192.0.2.10
zabbix_integration_publish_server_name: zabbix.example.test
```

The requested address must be a non-wildcard IPv4 address assigned to the host.
Certificate and key paths must be distinct canonical paths under the configured
`/etc/pki/tls/` directory. The role rejects symlinks, non-regular files,
unsafe directory ownership or modes, unknown pre-existing material, and
certificate identity drift.

Role-owned certificates are generated in a root-only staging directory and
validated for exact CN/SAN identity, self-signature, key match, and renewal
window. Key and certificate replacements are individually atomic and
interruption-recoverable, not pair-atomic. Publication succeeds only after
nginx owns the exact socket, serves the on-disk fingerprint for the requested
SNI, and answers a proxy-disabled local HTTPS request.

The role never opens a firewall, exports the private key, or establishes trust
for the self-signed certificate. External CA and reverse-proxy workflows remain
operator-owned.

## SELinux compatibility boundary

The role installs and verifies the exact EL10 policy packages needed to work
around a pinned `community.zabbix` dependency defect. It temporarily hides only
the SELinux status fact from the upstream server role, restores the complete
fact in an `always` block, and verifies that kernel enforcement remains active.
Remove this workaround only after the pinned upstream release no longer
requests the unavailable policy package.
