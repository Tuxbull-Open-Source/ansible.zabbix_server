# Basic example

This project installs `tuxbull.zabbix_server` on one documentation-only Rocky
Linux 10 host. Replace the host, SSH user, release suffixes, and secrets with
values resolved for your environment.

## Prepare

```bash
cp vault.example.yml vault.yml
$EDITOR vault.yml
ansible-vault encrypt vault.yml
ansible-galaxy role install -r requirements.yml
ansible-galaxy collection install -r requirements.yml
```

`vault.yml` is ignored by the role repository's `.gitignore`. Keep it out of
source control in your control project as well.

Both `CHANGE_ME` values are intentionally invalid. Replace them with unique
20-128 character secrets using only letters, numbers, `_`, and `-` before
encrypting the file.

## Validate and deploy

```bash
ansible-inventory -i inventory.yml --graph
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass --syntax-check
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
```

The second deployment must report `failed=0` and `changed=0`.

## Verify

```bash
ansible zabbix_servers -i inventory.yml -b --ask-vault-pass \
  -m ansible.builtin.command -a 'systemctl is-active postgresql zabbix-server nginx php-fpm zabbix-agent2'
ansible zabbix_servers -i inventory.yml -b --ask-vault-pass \
  -m ansible.builtin.shell -a "ss -H -lntp | grep -E '127\\.0\\.0\\.1:(8080|10050|10051)'"
```

The role does not open a firewall. The default frontend is available only at
`127.0.0.1:8080` on the managed host. Read the repository's security
documentation before enabling direct HTTPS publication.
