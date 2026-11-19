# Contributing

Use a feature branch and open a pull request. Keep changes focused and explain
what was tested.

Before opening a pull request:

```bash
tests/bootstrap-audit-artifacts.sh
python3 tests/run.py
git diff --check
```

Do not commit inventories, credentials, certificates, PSKs, private addresses,
internal hostnames, logs, generated state, or downloaded test artifacts.

Changes to `tasks/main.yml` or `tasks/include-file.yml` belong in
[`Tuxbull-Open-Source/ansible.template`](https://github.com/Tuxbull-Open-Source/ansible.template)
first. Those files are protected by exact hashes in this role.

Live package and service testing must use an authorized disposable Rocky Linux
10 system. Never run a service installation test on the Ansible controller.
