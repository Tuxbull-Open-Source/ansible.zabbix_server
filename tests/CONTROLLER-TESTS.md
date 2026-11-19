# Controller-only tests

`run.py` performs static contracts, copies this checkout into a real
`roles/tuxbull.zabbix_server/` harness, and runs syntax plus validation-only
Ansible tests if `ansible-playbook` is available. It never installs collections,
packages, or runs service tasks.

Contracts cover the eleven-artifact transitive lock, all three upstream Zabbix
NEVR expressions, PostgreSQL handler ordering, nginx absent/present fail-closed
ordering, required SELinux booleans, deterministic EPEL/fping transactions,
unsafe PHP secret characters, and synthetic IPv4/IPv6 listener output. Direct
HTTPS contracts cover strict opt-in validation, distinct canonical paths, exact
non-wildcard listener rendering, Admin-marker gating, protected ownership and v2
publication markers, transition teardown before stage 50, interruption-recoverable
staged validation and individually atomic installs, real OpenSSL
exact-SAN/self-signature/key tests, pre-package full
verification, post-reload nginx ownership/served fingerprint/GET checks, and
firewall non-ownership.
They also prove the artifact-backed server and agent EL10 policy defects, exact
repository-isolated policy ownership in the server stage, both temporary fact
overrides' ordering and nonrecursive `always` restoration, skipped agent sudo
boolean ownership, propagated failure semantics, and bracketed enforcing checks.
They also inspect the official checksum-verified Zabbix 8.0.0 source artifact for
the exact documented `user.login` `userData` result, filtered user lookup,
and password-update semantics; enforce complete
secret containment across stage 65; and run a synthetic loopback JSON-RPC server
to prove the already-desired-password path is unchanged and marker-gated by API
reauthentication.

```bash
python3 tests/run.py
```

These tests do not prove guest convergence. Remaining live gates are documented
in `docs/REUSE-AUDIT.md`.
