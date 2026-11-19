# Release and reuse audit

This role derives from
[`Tuxbull-Open-Source/ansible.template`](https://github.com/Tuxbull-Open-Source/ansible.template)
revision `479eda20a4317ca930de3b04b7d6c0fd87008951`. Its protected dispatcher files,
`LICENSE`, and `AGENTS.md` are unchanged.

Inspected the two supplied local Galaxy artifacts and downloaded every other
exact lock artifact to scratch for read-only checksum verification:

| Collection | Version | Release source | Artifact SHA-256 |
|---|---:|---|---|
| community.zabbix | 4.3.0 | tag commit `3d6c7738b2bea9f575982f540e1907c4fe732dd2` | `d30bbf022bc32bae89771f8d3611b31d9a524f5d384ff600067e7d0ba9480a5a` |
| fedora.linux_system_roles | 2.5.0 | embedded PostgreSQL role 1.9.0, commit `783e3b7b0fa1d94bab0eb5e7c8f8ecb6063f86bf` | `e5a485d0f06395f8dcf9fafe2267f3e8eb1d1aa27ec9b73162e4f8f84e53a046` |
| ansible.windows | 3.3.0 | Galaxy artifact | `1d5793991e342dcbbcd8377e62e3f8443d39c3e625272118dae895ed43f5539c` |
| ansible.netcommon | 8.4.0 | Galaxy artifact | `fafb603557bd4bb39aa40f56f3c3757d4a14d78259a57161c8f99db7fc81f33f` |
| ansible.utils | 6.0.1 | Galaxy artifact | `4fdd52d387fb4459ca5b80ce8b428f7a7173e40ad4106f24d7d74a8cd5aa04e9` |
| ansible.posix | 2.1.0 | Galaxy artifact | `5ff232cf69492a991f2a0990dbb23ef25a600b7e9209de6e33377a6ff08a8a29` |
| community.general | 12.4.0 | Galaxy artifact | `c26b6f4b2d964bfe0b8c9eec53962324f3ed77777d915db5791d802a3fed247a` |
| community.mysql | 4.1.0 | Galaxy artifact | `cc08dc63685ccc0fb4df0a3222cb14d59168941ca5215459805fd18149350643` |
| community.postgresql | 4.2.0 | Galaxy artifact | `1507b58bb3ff391ed7d847fc3f2985be15667761621899d0d7bbf92aee66e30a` |
| community.windows | 3.1.0 | Galaxy artifact | `9c3f950623e2d9777fc3167a0f893469be58620c4b8b9ef9e7556e5ccb28439a` |
| containers.podman | 1.19.0 | Galaxy artifact | `944c380094bcde001b510c22d8038ab9884eab3c7857aba21e2313fb79e7ed84` |

`requirements.yml` pins every dependency named by both artifacts' actual
`MANIFEST.json`. Companion versions are explicit versions satisfying the packaged constraints.
The helper downloads only to a caller-provided scratch path, verifies the exact
eleven-artifact set, every checksum, and the recursively closed `MANIFEST.json`
dependency graph. It does not install collections. The additional lock member is
`ansible.utils`, required by `ansible.netcommon >=3.0.0`; no further dependency
is declared by any of the eleven exact artifacts.

The local community.zabbix 4.3.0 artifact proves its nginx template emits
`listen <port>` and `listen [::]:<port>` without using
`zabbix_web_vhost_listen_ip`. This wrapper therefore reuses the exact frontend
RPM naming from `roles/zabbix_web/vars/RedHat.yml`, but owns a narrow local
nginx/PHP-FPM/frontend configuration so no wildcard listener can start.

No RPM release suffix is invented. Callers must supply the three release
suffixes after a Rocky 10 repository transaction resolution. Live convergence,
RPM signature/repository metadata validation, and the clean-VM transaction are
release gates.

The Rocky 10 prerequisite transaction is deterministic: install
`epel-release-10-9.el10` from disabled-by-default `extras` isolation, verify its
`6fedfc85` package signature and EPEL `gpgcheck`/key configuration, resolve only
`fping-5.2-3.el10_0|epel`, install with every other repository disabled, and
verify the resulting package signature. The pinned Zabbix server role disables
EPEL for its own package transaction; fping is therefore satisfied beforehand.

The pinned upstream frontend SELinux task enables
`httpd_can_network_connect_db`, `httpd_can_connect_zabbix`, and an LDAP boolean.
This wrapper reproduces the first two persistent booleans because it uses local
PostgreSQL and Zabbix; LDAP remains out of scope. Default RPM paths and the
Apache-owned PHP-FPM socket retain their packaged contexts, so no custom
`sefcontext` rule is required.

A live Rocky 10.2 resolution exposed a separate community.zabbix 4.3.0 server
regression: its EL10 SELinux include requests nonexistent `selinux-policy-epel`
before server package installation. Stage 40 now explicitly invokes the pinned
`community.zabbix.zabbix_repo` role, validates the exact official Zabbix 8.0
repository URL, signing-key path and `gpgcheck=1`, and resolves exact
`selinux-policy-targeted-extra-42.1.27-2.el10_3.2|crb` and
`zabbix-selinux-policy-2:8.0.0-release1.el10|zabbix` identities before an isolated
BaseOS/CRB/Zabbix transaction. Installed EVRs and Rocky/Zabbix RPM signing key IDs
are then checked, and the wrapper persistently owns `zabbix_can_network`.

Only after policy installation and an `Enforcing` kernel check does the wrapper
save `ansible_facts.selinux`, temporarily expose its status as disabled to the
upstream server role, and invoke that role with `zabbix_manage_repo: false`.
An `always` section restores the complete saved SELinux subfact after success or
failure. A restored-fact assertion and second `getenforce` check follow successful
upstream completion. This is a scoped compatibility workaround, not a change to
kernel SELinux state; remove it when the pinned collection's EL10 task stops
requesting `selinux-policy-epel`. Controller tests prove the ordering and upstream
artifact trigger. Public controller tests are self-contained. Maintainers can additionally supply
the audited source and package artifacts through the environment variables
documented in `tests/README.md` to rerun artifact-backed assertions.
