#!/usr/bin/env python3
"""Controller-only contract and installed-role harness tests."""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import re
import tarfile
import threading

LOOPBACK_8080 = re.compile(r"^LISTEN\s+\d+\s+\d+\s+127\.0\.0\.1:8080\s+")

ROLE = pathlib.Path(__file__).resolve().parents[1]
TEST_OWNER = pathlib.Path.home().owner()
TEST_GROUP = subprocess.check_output(["id", "-gn"], text=True).strip()
PROTECTED = ("tasks/main.yml", "tasks/include-file.yml", "LICENSE", "AGENTS.md")
PROTECTED_SHA256 = {
    "tasks/main.yml": "15be66db3da9d94d91278d3fa9096310df0b0089acb37409042ac58f7fc326b2",
    "tasks/include-file.yml": "37c6a2445cc7b3d164b6c848b9d7b249b01387a41711c21377cf60acedc143f4",
    "LICENSE": "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
    "AGENTS.md": "5faf15e5f9497f181223ffa92d871c85ac99470468953678c12d0db76f68155c",
}
AUDIT_DIR = pathlib.Path(os.environ.get("ZABBIX_AUDIT_DIR", "tests/artifacts"))


def text(path: str) -> str:
    return (ROLE / path).read_text()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def contracts() -> None:
    for relative in PROTECTED:
        actual = hashlib.sha256((ROLE / relative).read_bytes()).hexdigest()
        expected = PROTECTED_SHA256[relative]
        require(actual == expected, f"protected file changed: {relative}")

    # Public identity and operator documentation must move together while the
    # established zabbix_integration_* variable API remains compatible.
    metadata = text("meta/main.yml")
    readme = text("README.md")
    example_files = {
        "README.md",
        "inventory.yml",
        "playbook.yml",
        "requirements.yml",
        "vault.example.yml",
    }
    example_dir = ROLE / "examples/basic"
    require("role_name: zabbix_server" in metadata, "Galaxy role identity drift")
    require("# tuxbull.zabbix_server" in readme, "README role identity drift")
    require("ansible.zabbix_server.git" in readme, "renamed repository URL missing")
    retired_role_identity = "tuxbull.zabbix_" + "integration"
    require(retired_role_identity not in "\n".join(
        path.read_text(errors="ignore") for path in ROLE.rglob("*")
        if path.is_file() and "collections" not in path.parts and ".git" not in path.parts
        and "__pycache__" not in path.parts),
        "retired Galaxy identity remains in a tracked role file")
    require({path.name for path in example_dir.iterdir()} == example_files,
            "basic example is incomplete or contains an unexpected file")
    example_text = "\n".join((example_dir / name).read_text() for name in sorted(example_files))
    for token in ("tuxbull.zabbix_server", "ansible.zabbix_server.git",
                  "zabbix-server.example.test", "192.0.2.10",
                  "vault_zabbix_database_password", "vault_zabbix_admin_password"):
        require(token in example_text, f"basic example contract missing: {token}")
    require("zabbix_integration_database_password" in example_text and
            "zabbix_integration_admin_password" in example_text,
            "compatibility variable API is missing from the basic example")
    retired_repository_identity = "ansible.zabbix_" + "integration"
    for private_token in (retired_repository_identity, retired_role_identity,
                          "10.0.", "10.1.", "172.16.", "192.168."):
        require(private_token not in example_text,
                f"basic example contains retired/private identifier: {private_token}")
    for page in ("docs/SECURITY.md", "docs/ARCHITECTURE.md", "docs/VARIABLES.md"):
        require(f"]({page})" in readme, f"README does not link {page}")

    requirements = text("requirements.yml")
    for token in (
        "community.zabbix\n    version: 4.3.0",
        "fedora.linux_system_roles\n    version: 2.5.0",
    ):
        require(token in requirements, f"missing exact pin: {token}")
    require("ansible.utils\n    version: 6.0.1" in requirements,
            "missing ansible.netcommon's pinned ansible.utils dependency")
    require(requirements.count("  - name:") == 11, "collection lock is not exactly eleven entries")
    checksum_helper = text("scripts/verify_collection_artifacts.py")
    require(checksum_helper.count('tar.gz": "') == 11, "checksum lock is incomplete")
    require('version: "*"' not in requirements and "version: '*'" not in requirements,
            "wildcard collection pin")

    task_files = list((ROLE / "tasks").rglob("*.yml"))
    implementation = [p for p in task_files if p.name not in {"main.yml", "include-file.yml"}]
    lifecycle_tasks = {
        ROLE / "tasks/Rocky-10/zabbix_server/schema_service_pre.yml",
        ROLE / "tasks/Rocky-10/zabbix_server/schema_service_post.yml",
    }
    require(all((p in lifecycle_tasks) or
                (len(p.name) > 2 and p.name[:2].isdigit() and p.name[2] == "_")
                for p in implementation),
            "task basename is not two-digit numbered")
    shared = list((ROLE / "tasks/shared").glob("*.yml"))
    require([p.name for p in shared] == ["00_validate.yml"], "shared tasks not platform-neutral")
    require(not any(p.is_dir() and p.name != "Rocky-10" for p in (ROLE / "tasks").iterdir()
                    if p.name not in {"shared"}), "unsupported platform directory")

    combined = "\n".join(p.read_text() for p in implementation)
    for forbidden in ("community.general.filesystem", "ansible.posix.mount", "lvg:", "lvol:",
                      "firewalld:", "parted:"):
        require(forbidden not in combined, f"forbidden ownership task: {forbidden}")
    for expected in ("zabbix_server_database_creation: true", "zabbix_server_database_sqlload: false",
                     "zabbix_server_database_timescaledb: false",
                     "zabbix_server_allowunsupporteddbversions: false",
                     "zabbix_server_dbpassword_hash_method: scram-sha-256",
                     "zabbix_api_create_hostgroup: false", "zabbix_api_create_hosts: false",
                     "zabbix_agent2: true", "apply:", "no_log: true", "diff: false",
                     "listen_addresses: \"'localhost'\"", "password_encryption: \"'scram-sha-256'\""):
        require(expected in combined, f"missing safety contract: {expected}")
    defaults = text("defaults/main.yml")
    require("password" not in defaults.lower(), "secret-like default found")
    require("zabbix_integration_publish: false" in defaults, "publication not closed")
    require("zabbix_integration_admin_bootstrap: false" in defaults,
            "Admin bootstrap is not explicitly opt-in")
    require("admin_bootstrap_complete" not in defaults + combined,
            "caller-controlled bootstrap completion claim remains")
    require("zabbix_integration_zabbix_version: \"8.0\"" in defaults, "Zabbix version drift")
    require("zabbix_integration_postgresql_version: \"16\"" in defaults, "PostgreSQL version drift")
    require("connection: local" in text("tests/test.yml"), "test is not localhost/local")
    require("zabbix_integration_publish_listen_ipv4" in defaults and
            "zabbix_integration_publish_server_name" in defaults,
            "direct HTTPS publication inputs are missing")

    # Semantic listener check: parse every effective nginx listen directive,
    # rather than merely checking for a desired source string.
    nginx_main = text("templates/nginx.conf.j2")
    nginx_vhost = text("templates/zabbix-nginx.conf.j2")
    nginx_https = text("templates/zabbix-https.conf.j2")
    uncommented = "\n".join(line.split("#", 1)[0] for line in
                            (nginx_main + nginx_vhost + nginx_https).splitlines())
    listeners = re.findall(r"(?m)^\s*listen\s+([^;]+);", uncommented)
    require(listeners == ["127.0.0.1:8080",
                           "{{ zabbix_integration_publish_listen_ipv4 }}:443 ssl"],
            f"frontend listeners are not exact: {listeners}")
    require("include /etc/nginx/conf.d/zabbix.conf;" in nginx_main, "only the owned vhost must be included")
    require("include /etc/nginx/zabbix-tls-enabled/*.conf;" in nginx_main,
            "optional TLS include is missing")
    require("default_server" not in uncommented and "[::]" not in uncommented and
            "listen 443" not in uncommented and "0.0.0.0:443" not in uncommented,
            "wildcard/default nginx listener found")
    web_tasks = text("tasks/Rocky-10/50_zabbix_web.yml")
    prerequisites = text("tasks/Rocky-10/10_prerequisites.yml")
    secured_expression_match = re.search(
        r"(?m)^    _zabbix_integration_frontend_secured: >-\n"
        r"(?P<body>(?:      .*\n)+)", prerequisites)
    require(secured_expression_match is not None,
            "published lifecycle expression could not be extracted")
    secured_expression = "\n".join(
        line[6:] for line in secured_expression_match.group("body").splitlines())
    require("_zabbix_integration_publish" not in secured_expression,
            "published lifecycle expression contains a misspelled publication variable")
    require("failed_when: false" not in prerequisites[prerequisites.index("Stop nginx when"):],
            "nginx stop is fail-open")
    require("'nginx.service' in ansible_facts.services" in prerequisites,
            "absent nginx service is not handled explicitly")
    require(prerequisites.index("Discover services") < prerequisites.index("Mask nginx")
            < prerequisites.index("Install exact EPEL") < prerequisites.index("Install minimal web prerequisites")
            < prerequisites.index("Refresh services") < prerequisites.index("Stop packaged nginx")
            < prerequisites.index("inactive before configuration"), "prerequisite nginx safety order changed")
    require(web_tasks.index("Install exact Zabbix frontend packages") < web_tasks.index("Stop nginx after")
            < web_tasks.index("inactive after frontend") < web_tasks.index("Install fail-closed"),
            "frontend package/config nginx safety order changed")
    require(web_tasks.index("nginx -t") < web_tasks.index("Unmask nginx")
            < web_tasks.index("still inactive immediately before startup")
            < web_tasks.index("Start loopback-only nginx"),
            "nginx mask/configuration/start ordering changed")
    require("masked: false" in web_tasks and "systemctl mask nginx.service" in prerequisites,
            "nginx is not masked across package/configuration work")
    fail_closed = text("tasks/Rocky-10/70_fail_closed.yml")
    https_tasks = text("tasks/Rocky-10/67_https_publication.yml")
    marker = "/var/lib/zabbix-integration/frontend-secured"
    require(marker in prerequisites and marker in fail_closed,
            "verified frontend lifecycle marker is not read and written")
    require(prerequisites.index("Validate TLS publication directory chain before lifecycle changes") <
            prerequisites.index("Inspect HTTPS lifecycle and material paths")
            < prerequisites.index("Validate marked local certificate state before package work")
            < prerequisites.index("Stop nginx when the published lifecycle is not exact")
            < prerequisites.index("Remove stale direct HTTPS virtual host while nginx is stopped")
            < prerequisites.index("Mask nginx")
            < prerequisites.index("Install exact EPEL"),
            "secure frontend preflight does not precede package work")
    require(prerequisites.count("when: not _zabbix_integration_frontend_secured") >= 3 and
            web_tasks.count("when: not _zabbix_integration_frontend_secured") >= 4,
            "first-run stop/mask/start lifecycle is not marker-gated")
    require("Refuse prerequisite package drift on a verified frontend" in prerequisites and
            "not _zabbix_integration_prerequisite_transaction.changed" in prerequisites and
            "not _zabbix_integration_epel_release_transaction.changed" in prerequisites and
            "not _zabbix_integration_fping_transaction.changed" in prerequisites and
            "Refuse frontend package drift on a verified frontend" in web_tasks and
            "not _zabbix_integration_frontend_package_transaction.changed" in web_tasks,
            "verified lifecycle does not reject package drift")
    require(web_tasks.index("Install fail-closed nginx main configuration")
            < web_tasks.index("nginx -t")
            < web_tasks.index("Reload verified nginx after configuration changes"),
            "verified nginx configuration is not validated before reload")
    require("_zabbix_integration_nginx_main_configuration.changed or" in web_tasks and
            "_zabbix_integration_php_fpm_configuration.changed" in web_tasks,
            "verified services are not restarted only for owned configuration changes")
    require(fail_closed.index("Confirm exactly one loopback frontend socket owned by nginx")
            < fail_closed.index("Record successfully validated exact HTTPS lifecycle"),
            "frontend lifecycle marker is recorded before listener validation")
    require("community.zabbix.zabbix_web" not in web_tasks,
            "unsafe upstream nginx web role is still composed")
    require(all(token in web_tasks for token in ("ansible.posix.seboolean", "persistent: true",
            "httpd_can_network_connect_db", "httpd_can_connect_zabbix")),
            "required persistent frontend SELinux booleans are missing")
    require(https_tasks.index("Inspect verified Admin bootstrap marker") <
            https_tasks.index("Require verified Admin bootstrap state") <
            https_tasks.index("Revalidate TLS publication directory chain immediately before creation") <
            https_tasks.index("Create protected TLS material directory") <
            https_tasks.index("Validate created TLS publication directory chain before material mutation") <
            https_tasks.index("Create protected HTTPS lifecycle state directory") <
            https_tasks.index("Generate candidate key and self-signed certificate") <
            https_tasks.index("Fully validate candidate certificate pair") <
            https_tasks.index("Install validated private key with an atomic file replacement") <
            https_tasks.index("Install exact direct HTTPS virtual host") <
            https_tasks.index("Validate nginx after publication configuration") <
            https_tasks.index("Reload nginx only after publication validation") <
            https_tasks.index("Validate served certificate and fingerprint"),
            "HTTPS fail-closed ordering changed")
    for token in ("ansible.builtin.tempfile:", "openssl", "subjectAltName=DNS:",
                  "zabbix-https-validate", "https-certificate-v2|", "--served",
                  'mode: "0600"', 'mode: "0644"', "systemctl is-active nginx",
                  "use_proxy: false", "validate_certs: false"):
        require(token in https_tasks, f"missing HTTPS safety contract: {token}")
    require("creates:" not in https_tasks, "HTTPS generation still uses direct creates")
    require("-check_ss_sig" in text("files/zabbix_https_validate.py"),
            "self-signature validation is missing")
    require("lstat()" in text("files/zabbix_https_validate.py") and
            "st_mode & 0o022" in text("files/zabbix_https_validate.py") and
            "required_owner_uid: int | None = 0" in text("files/zabbix_https_validate.py"),
            "TLS directory chain does not enforce no-follow, ownership, and permissions")
    require("firewalld:" not in https_tasks and "ansible.posix.firewalld" not in https_tasks,
            "HTTPS publication mutates firewall state")
    require("slurp:" not in https_tasks[https_tasks.index("Generate candidate key and self-signed certificate"):],
            "TLS material is read back after generation")
    require(prerequisites.index("Stop nginx when the published lifecycle is not exact") <
            prerequisites.index("Remove stale direct HTTPS virtual host while nginx is stopped") <
            prerequisites.index("Refuse unknown preexisting HTTPS material after exposure is removed") <
            prerequisites.index("Install exact EPEL"),
            "unknown material is refused before exposure removal or after package work")
    for token in ("_zabbix_integration_certificate_stat.isreg", "mode | default('') == '0644'",
                  "_zabbix_integration_private_key_stat.isreg", "mode | default('') == '0600'",
                  "served_fingerprint", "users:", "nginx"):
        require(token in prerequisites, f"pre-package exact HTTPS verification missing: {token}")

    # Lifecycle decision table: only an ownership marker permits interrupted
    # individual-file installation recovery; unknown material refuses overwrite.
    lifecycle = {}
    for owned in (False, True):
        for cert_exists in (False, True):
            for key_exists in (False, True):
                unknown = (cert_exists or key_exists) and not owned
                recover = owned and not (cert_exists and key_exists)
                lifecycle[(owned, cert_exists, key_exists)] = (unknown, recover)
    require(lifecycle[(False, False, False)] == (False, False) and
            lifecycle[(False, True, False)] == (True, False) and
            lifecycle[(False, False, True)] == (True, False) and
            lifecycle[(False, True, True)] == (True, False) and
            lifecycle[(True, True, False)] == (False, True) and
            lifecycle[(True, False, True)] == (False, True),
            f"HTTPS ownership/recovery decision table changed: {lifecycle}")

    # Exercise exact identity validation against real OpenSSL artifacts.
    validator = str(ROLE / "files/zabbix_https_validate.py")
    with tempfile.TemporaryDirectory() as tls_tmp:
        tls = pathlib.Path(tls_tmp)

        def generate(name: str, san: str) -> tuple[pathlib.Path, pathlib.Path]:
            cert = tls / f"{name}.crt"
            key = tls / f"{name}.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-days", "2", "-subj", "/CN=zabbix.example.test", "-addext",
                f"subjectAltName={san}", "-keyout", str(key), "-out", str(cert),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return cert, key

        exact_cert, exact_key = generate(
            "exact", "DNS:zabbix.example.test,IP:192.0.2.10")
        exact = subprocess.run([
            "python3", validator, "--cert", str(exact_cert), "--key", str(exact_key),
            "--dns", "zabbix.example.test", "--ip", "192.0.2.10", "--checkend", "1",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(exact.returncode == 0 and json.loads(exact.stdout)["valid"],
                "real exact-SAN self-signed candidate was rejected")

        extra_cert, extra_key = generate(
            "extra", "DNS:zabbix.example.test,IP:192.0.2.10,DNS:extra.example.test")
        extra = subprocess.run([
            "python3", validator, "--cert", str(extra_cert), "--key", str(extra_key),
            "--dns", "zabbix.example.test", "--ip", "192.0.2.10", "--checkend", "1",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(extra.returncode != 0, "certificate with an extra SAN was accepted")

        mismatch = subprocess.run([
            "python3", validator, "--cert", str(exact_cert), "--key", str(extra_key),
            "--dns", "zabbix.example.test", "--ip", "192.0.2.10", "--checkend", "1",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(mismatch.returncode != 0, "mismatched certificate/private key was accepted")
        equal = subprocess.run([
            "python3", validator, "--cert", str(exact_cert), "--key", str(exact_cert),
            "--dns", "zabbix.example.test", "--ip", "192.0.2.10", "--checkend", "1",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(equal.returncode != 0, "identical certificate/key path was accepted")
        cert_link = tls / "linked.crt"
        cert_link.symlink_to(exact_cert)
        linked = subprocess.run([
            "python3", validator, "--cert", str(cert_link), "--key", str(exact_key),
            "--dns", "zabbix.example.test", "--ip", "192.0.2.10", "--checkend", "1",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(linked.returncode != 0, "symlinked certificate path was accepted")

        # A missing tail below the root-owned TLS baseline is valid. A symlinked
        # component must be rejected without creating anything in its target.
        missing_tail = f"/etc/zabbix-chain-test-{os.getpid()}/nested"
        chain_probe = (
            "import importlib.util,json,sys;"
            "s=importlib.util.spec_from_file_location('validator',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "print(json.dumps(m.validate_directory_chain(sys.argv[2],"
            "required_baseline=('/etc',),required_owner_uid=None),sort_keys=True))"
        )
        missing_chain = subprocess.run([
            "python3", "-c", chain_probe, validator, missing_tail,
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(missing_chain.returncode == 0 and
                not json.loads(missing_chain.stdout)["exists"],
                "safe TLS directory chain with a missing tail was rejected")
        existing_chain = subprocess.run([
            "python3", "-c", chain_probe, validator, "/etc",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(existing_chain.returncode == 0 and
                json.loads(existing_chain.stdout)["exists"],
                "safe existing root-owned directory was rejected")

        outside = tls / "outside"
        outside.mkdir()
        link = tls / "linked-directory"
        link.symlink_to(outside, target_is_directory=True)
        before = set(outside.iterdir())
        symlink_chain = subprocess.run([
            "python3", "-c", chain_probe, validator, str(link / "material"),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(symlink_chain.returncode != 0 and
                "symbolic-link directory component rejected" in symlink_chain.stderr and
                set(outside.iterdir()) == before,
                "symlinked TLS directory chain was not rejected without outside writes")

    postgres_tasks = text("tasks/Rocky-10/20_postgresql.yml")
    require(postgres_tasks.index("include_role") < postgres_tasks.index("flush_handlers"),
            "PostgreSQL handlers are not flushed after the upstream role")

    prereq = text("tasks/Rocky-10/10_prerequisites.yml")
    for token in ("epel-release-{{ zabbix_integration_epel_release_evr }}", "enablerepo: extras",
                  "fping-{{ zabbix_integration_fping_evr }}", "--enablerepo=epel",
                  "'%{name}-%{evr}|%{repoid}'".replace("'", '"')):
        require(token in prereq, f"missing deterministic EPEL/fping contract: {token}")
    require(prereq.count('disablerepo: "*"') == 2 and "--disablerepo=*" in prereq,
            "EPEL/fping transactions are not repository-isolated")
    require('"%{RSAHEADER:pgpsig}"' in prereq and "e37ed158" in prereq and
            "stdout | lower" in prereq and "regex_search" in prereq,
            "fping RSA header signature verification is not exact and case-normalized")

    # Verify the audited RPM itself carries the exact fping signing key ID.
    fping_value = os.environ.get("FPING_RPM")
    if fping_value:
        fping_artifact = pathlib.Path(fping_value)
        require(fping_artifact.is_file(), "FPING_RPM does not point to a file")
        rpm = shutil.which("rpm")
        require(rpm is not None, "rpm is required for artifact-backed signature testing")
        fping_signature = subprocess.run(
            [rpm, "-qp", "--qf", "%{RSAHEADER:pgpsig}", str(fping_artifact)],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.lower()
        require(re.search(r"key id (?:[0-9a-f]{8})?e37ed158(?:\\b|$)", fping_signature) is not None,
                f"audited fping RPM has unexpected RSA header signature: {fping_signature!r}")

    validation = text("tasks/shared/00_validate.yml")
    require("^[A-Za-z0-9_-]{20,128}$" in validation,
            "URL-safe secret validation is missing")
    require("zabbix_integration_agent_server == '127.0.0.1'" in validation,
            "agent loopback input is not literal-guarded")
    agent_tasks = text("tasks/Rocky-10/60_zabbix_agent2.yml")
    require('zabbix_agent_server: "{{ zabbix_integration_agent_server }}"' in agent_tasks and
            'zabbix_agent_serveractive: "{{ zabbix_integration_agent_server }}"' in agent_tasks,
            "agent passive/active upstream inputs are not both exact")
    require("zabbix_agent_statusport: null" in agent_tasks,
            "upstream wildcard Agent 2 status endpoint is not disabled")
    require("Require only the loopback Agent 2 listener" in agent_tasks and
            "^LISTEN\\s+\\d+\\s+\\d+\\s+127\\.0\\.0\\.1:10050\\s+\\S+\\s+users:" in agent_tasks and
            "unexpected non-loopback or auxiliary listener" in agent_tasks,
            "exact Agent 2 listener verification is missing")
    require("zabbix_integration_timezone is string" in validation and
            "zabbix_integration_timezone | length <= 128" in validation and "\\Z" in validation,
            "strict bounded timezone validation is missing")
    require("publish_listen_ipv4 != '0.0.0.0'" in validation and
            "publish_certificate_path | normpath" in validation and
            "publish_certificate_renewal_days" in validation,
            "HTTPS wildcard, path identity, or renewal validation is missing")
    require("zabbix_integration_admin_bootstrap | bool" in validation and
            "publish_listen_ipv4 is match" in validation and
            "publish_server_name is match" in validation and
            "^/etc/pki/tls" in validation,
            "strict HTTPS input validation is missing")
    php = text("templates/zabbix.conf.php.j2")
    require("'{{ zabbix_integration_database_password }}'" in php,
            "PHP password rendering changed without matching validation")
    for value in ("safe_URL-secret-123456", "has'apostrophe1234567890",
                  r"has\\backslash1234567890", "has$dollar1234567890123", "has\nnewline123456789"):
        accepted = re.fullmatch(r"[A-Za-z0-9_-]{20,128}", value) is not None
        require(accepted == (value == "safe_URL-secret-123456"),
                f"unexpected secret alphabet result for {value!r}")

    require("select('match'" in fail_closed and "127\\.0\\.0\\.1:8080" in fail_closed and
            'users:\\(\\("nginx",' in fail_closed and "\\\\s" not in fail_closed and
            "\\\\d" not in fail_closed,
            "runtime listener ownership verification is not exact")

    # Stage 65 must authenticate first on every enabled run, use documented
    # userData identity, and contain every secret/token.
    bootstrap = text("tasks/Rocky-10/65_admin_bootstrap.yml")
    require("when: zabbix_integration_admin_bootstrap | bool" in bootstrap,
            "Admin bootstrap is not authorization-gated")
    require(bootstrap.index("Try the desired Admin credential") <
            bootstrap.index("Log in once with the vendor-default") <
            bootstrap.index("Rotate only the login-returned Admin password") <
            bootstrap.index("Log in with the rotated Admin credential") <
            bootstrap.index("Record verified Admin API bootstrap"),
            "Admin bootstrap ordering changed")
    require(bootstrap.count("userData: true") == 3 and "current: true" not in bootstrap,
            "login/verification does not use documented userData and filter semantics")
    require(bootstrap.count("filter:") == 2 and bootstrap.count("username: Admin") == 5 and
            "_zabbix_integration_admin_discovery" not in bootstrap,
            "Admin verification retains undocumented current lookup or discovery request")
    require("current_passwd: zabbix" in bootstrap and
            "userid: \"{{ _zabbix_integration_default_login.json.result.userid }}\"" in bootstrap,
            "password update does not use current credential and login-returned userid")
    require("Authorization: \"Bearer {{ _zabbix_integration_desired_login.json.result.sessionid }}\"" in bootstrap and
            "Authorization: \"Bearer {{ _zabbix_integration_default_login.json.result.sessionid }}\"" in bootstrap and
            "Authorization: \"Bearer {{ _zabbix_integration_rotated_login.json.result.sessionid }}\"" in bootstrap,
            "a login result is not using its sessionid bearer token")
    require("UPDATE users" not in bootstrap.upper() and "psql" not in bootstrap.lower(),
            "Admin bootstrap contains a direct database mutation")
    uri_calls = bootstrap.count("ansible.builtin.uri:")
    require(uri_calls == 6, f"stage 65 URI call count changed: {uri_calls}")
    require(bootstrap.count("use_proxy: false") == uri_calls,
            "every stage-65 URI call must explicitly disable proxy use")
    require(bootstrap.count("no_log: true") == bootstrap.count("ansible.builtin.") + 2,
            "a stage-65 task can expose a password or nested API result")
    require(bootstrap.count("diff: false") == bootstrap.count("ansible.builtin.") + 2,
            "a stage-65 task can diff a password or nested API result")
    require("/var/lib/zabbix-integration/admin-api-bootstrap" in bootstrap and
            'mode: "0600"' in bootstrap and 'mode: "0700"' in bootstrap,
            "verified Admin marker is not root-only")
    require("admin-api-bootstrap" not in bootstrap[:bootstrap.index("Record verified Admin API bootstrap")],
            "Admin marker is trusted before API reauthentication")
    require('mode: "0700"' in fail_closed and 'mode: "0755"' not in fail_closed,
            "stage 70 relaxes the protected state directory")
    prerequisites = text("tasks/Rocky-10/10_prerequisites.yml")
    for module in ("ansible.builtin.stat:", "ansible.builtin.slurp:"):
        start = prerequisites.index(module)
        require("become: true" in prerequisites[start:start + 600],
                f"task 10 marker {module} does not use privilege escalation")
    synthetic = {
        "loopback": ["LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*"],
        "ipv4_any": ["LISTEN 0 511 0.0.0.0:8080 0.0.0.0:*"],
        "ipv6_any": ["LISTEN 0 511 [::]:8080 [::]:*"],
        "extra": ["LISTEN 0 511 127.0.0.1:8080 0.0.0.0:*", "LISTEN 0 511 [::1]:8080 [::]:*"],
    }
    results = {name: len(lines) == 1 and LOOPBACK_8080.match(lines[0]) is not None
               for name, lines in synthetic.items()}
    require(results == {"loopback": True, "ipv4_any": False, "ipv6_any": False, "extra": False},
            f"synthetic listener policy mismatch: {results}")

    # Artifact-backed regression: prove why the upstream web role cannot safely
    # own nginx, and prove our exact RPM expression matches its RedHat vars.
    zabbix_artifact = AUDIT_DIR / "community-zabbix-4.3.0.tar.gz"
    require(zabbix_artifact.is_file(),
            "run tests/bootstrap-audit-artifacts.sh before the test suite")
    require(hashlib.sha256(zabbix_artifact.read_bytes()).hexdigest() ==
            "d30bbf022bc32bae89771f8d3611b31d9a524f5d384ff600067e7d0ba9480a5a",
            "audited community.zabbix artifact checksum mismatch")
    with tarfile.open(zabbix_artifact, "r:gz") as archive:
        upstream_nginx = archive.extractfile("roles/zabbix_web/templates/nginx_vhost.conf.j2").read().decode()
        upstream_redhat = archive.extractfile("roles/zabbix_web/vars/RedHat.yml").read().decode()
        upstream_server_redhat = archive.extractfile("roles/zabbix_server/vars/RedHat.yml").read().decode()
        upstream_agent_redhat = archive.extractfile("roles/zabbix_agent/vars/RedHat.yml").read().decode()
        upstream_selinux = archive.extractfile("roles/zabbix_web/tasks/selinux.yml").read().decode()
    upstream_listeners = re.findall(r"(?m)^\s*listen\s+([^;]+);", upstream_nginx)
    require("{{ zabbix_web_vhost_port }}" in upstream_listeners,
            "audited upstream wildcard IPv4 listener changed")
    require("[::]:{{ zabbix_web_vhost_port }}" in upstream_listeners,
            "audited upstream wildcard IPv6 listener changed")
    require("zabbix_web_vhost_listen_ip" not in upstream_nginx,
            "audited upstream now honors its listen-IP variable; reassess divergence")
    require('"zabbix-web-{{ zabbix_server_database }}-{{ zabbix_web_version }}.{{ zabbix_web_version_minor }}"'
            in upstream_redhat, "audited upstream frontend RPM expression changed")
    require('"zabbix-{{ zabbix_web_http_server }}-conf-{{ zabbix_web_version }}.{{ zabbix_web_version_minor }}"'
            in upstream_redhat, "audited upstream web-conf RPM expression changed")
    require('"zabbix-server-{{ zabbix_server_database }}-{{ zabbix_server_version }}.{{ zabbix_server_version_minor }}"'
            in upstream_server_redhat and
            '"zabbix-sql-scripts-{{ zabbix_server_version }}.{{ zabbix_server_version_minor }}"'
            in upstream_server_redhat, "audited upstream server RPM expressions changed")
    require('"{{ zabbix_agent2 | ternary(\'zabbix-agent2\', \'zabbix-agent\') }}-{{ zabbix_agent_version }}.{{ zabbix_agent_version_minor }}"'
            in upstream_agent_redhat, "audited upstream agent RPM expression changed")
    require(all(x in upstream_selinux for x in ("httpd_can_network_connect_db", "httpd_can_connect_zabbix")),
            "audited upstream frontend SELinux policy changed")

    # Official Zabbix 8.0.0 source, verified against the publisher's SHA-256,
    # is the semantic authority for this bootstrap request shape.
    zabbix80 = AUDIT_DIR / "zabbix-8.0.0.tar.gz"
    require(zabbix80.is_file(),
            "run tests/bootstrap-audit-artifacts.sh before the test suite")
    require(hashlib.sha256(zabbix80.read_bytes()).hexdigest() ==
            "55469ac599fd1443370ecf4288655d4d62109ad3a686711c4f3e0d428338ca77",
            "official Zabbix 8.0.0 source checksum mismatch")
    with tarfile.open(zabbix80, "r:gz") as archive:
        cuser = archive.extractfile(
            "zabbix-8.0.0/ui/include/classes/api/services/CUser.php"
        ).read().decode()
    for semantic in ("public function login(array $data)",
                     "'username' =>\t['type' => API_STRING_UTF8, 'flags' => API_REQUIRED",
                     "'password' =>\t['type' => API_STRING_UTF8, 'flags' => API_REQUIRED",
                     "'userData' =>\t['type' => API_FLAG]",
                     "return array_key_exists('userData', $data) && $data['userData'] ? $db_user : $db_user['sessionid'];",
                     "'sessionid' => $db_user['sessionid']",
                     "'filter' =>\t\t\t\t\t['type' => API_FILTER",
                     "'userid' =>\t\t\t\t\t\t['type' => API_ID, 'flags' => API_REQUIRED]",
                     "'current_passwd' =>", "'passwd' =>",
                     "Current password is mandatory.",
                     "return ['userids' => array_column($users, 'userid')]"):
        require(semantic in cuser, f"Zabbix 8.0 API semantic changed: {semantic}")
    role_vars = text("vars/main.yml")
    require("zabbix-web-pgsql-{{ zabbix_integration_zabbix_version }}.{{ zabbix_integration_web_release }}"
            in role_vars, "local frontend RPM expression differs from audited upstream")
    require("zabbix-nginx-conf-{{ zabbix_integration_zabbix_version }}.{{ zabbix_integration_web_release }}"
            in role_vars, "local nginx-conf RPM expression differs from audited upstream")
    server = text("tasks/Rocky-10/40_zabbix_server.yml")
    server_pre = text("tasks/Rocky-10/zabbix_server/schema_service_pre.yml")
    server_post = text("tasks/Rocky-10/zabbix_server/schema_service_post.yml")
    server_lifecycle = server_pre + server_post
    agent = text("tasks/Rocky-10/60_zabbix_agent2.yml")
    require(all(x in server for x in ("zabbix_server_version:", "zabbix_server_version_minor:",
                                       "zabbix_server_database: pgsql")),
            "server role does not supply every upstream NEVR component")
    require(all(x in server for x in (
        "zabbix_server_manage_service: false",
        "zabbix_server_conf_file: \"{{ zabbix_integration_server_config_path }}\"",
        "zabbix_server/schema_service_pre.yml",
        "zabbix_server/schema_service_post.yml")),
        "server composition does not bracket upstream with lifecycle tasks")
    require(all(x in server_lifecycle for x in (
        "SELECT to_regclass('public.dbversion')::text AS dbversion",
        "_zabbix_integration_schema_state.query_result == [{'dbversion': none}]",
        "/usr/share/zabbix/sql-scripts/postgresql/server.sql.gz",
        "SELECT mandatory FROM dbversion",
        "Stop a running server before repairing an incomplete schema",
        "Clear the deliberately suppressed upstream server handler",
        "Keep Zabbix server stopped until an incomplete schema is repaired",
        "Restart an already active Zabbix server only for configuration drift",
        "Enable and start Zabbix server after schema verification")),
        "non-failing first-schema lifecycle is incomplete")
    require(server_post.index("Detect the packaged Zabbix schema without an expected SQL failure") <
            server_post.index("Import the pinned packaged PostgreSQL schema only when absent") <
            server_post.index("Verify the Zabbix schema version table after optional import") <
            server_post.index("Enable and start Zabbix server after schema verification"),
            "schema detection/import/verification/service ordering is unsafe")
    require(all(x in agent for x in ("zabbix_agent_version:", "zabbix_agent_version_minor:",
                                     "zabbix_agent2: true")),
            "agent role does not supply every upstream NEVR component")

    # community.zabbix 4.3.0 EL10 regressions and the narrowly scoped workarounds.
    with tarfile.open(zabbix_artifact, "r:gz") as archive:
        upstream_server_main = archive.extractfile("roles/zabbix_server/tasks/main.yml").read().decode()
        upstream_server_selinux = archive.extractfile("roles/zabbix_server/tasks/selinux.yml").read().decode()
        upstream_agent_configure = archive.extractfile("roles/zabbix_agent/tasks/configure.yml").read().decode()
        upstream_agent_selinux = archive.extractfile("roles/zabbix_agent/tasks/selinux.yml").read().decode()
    require("ansible_facts.selinux.status" in upstream_server_main and
            "selinux-policy-epel" in upstream_server_selinux,
            "upstream server EL10 SELinux defect changed; remove/reassess the workaround")
    require("ansible_facts.selinux.status" in upstream_agent_configure and
            "selinux-policy-epel" in upstream_agent_selinux and
            "name: zabbix_run_sudo" in upstream_agent_selinux,
            "upstream agent EL10 SELinux defect changed; remove/reassess the workaround")
    defaults = text("defaults/main.yml")
    validation = text("tasks/shared/00_validate.yml")
    for token in ("42.1.27-2.el10_3.2", "2:8.0.0-release1.el10"):
        require(token in defaults and token in validation, f"SELinux policy pin is not fixed: {token}")
    for token in ("community.zabbix.zabbix_repo", "zabbix_repo_version:",
                  "selinux-policy-targeted-extra-{{ zabbix_integration_selinux_policy_targeted_extra_evr }}",
                  "zabbix-selinux-policy-{{ zabbix_integration_zabbix_selinux_policy_evr }}",
                  "--enablerepo=crb", "--enablerepo=zabbix", 'disablerepo: "*"',
                  "disable_gpg_check: false", "key: 6fedfc85", "key: b5333005",
                  "name: zabbix_can_network", "persistent: true", "zabbix_manage_repo: false",
                  "_zabbix_integration_original_selinux_fact", "status': 'disabled'", "always:",
                  "ansible_facts.selinux.status == 'enabled'", "command: getenforce"):
        require(token in server, f"missing scoped SELinux workaround contract: {token}")
    require(server.count("command: getenforce") == 2, "enforcing mode is not checked around workaround")
    repo = server.index("community.zabbix.zabbix_repo")
    policy = server.index("Install exact enforcing SELinux policy packages")
    boolean = server.index("Own the persistent Zabbix network SELinux boolean")
    enforcing_before = server.index("Verify SELinux remains enforcing before")
    hide = server.index("Temporarily hide SELinux")
    include_server = server.index("Configure Zabbix server and own database/schema lifecycle")
    restore = server.index("Restore the real SELinux fact even after upstream failure")
    restored_assert = server.index("Verify the SELinux fact was restored")
    enforcing_after = server.index("Verify SELinux remains enforcing after")
    require(repo < policy < boolean < enforcing_before < hide < include_server < restore <
            restored_assert < enforcing_after, "scoped SELinux workaround ordering changed")
    require(server.index("always:") < restore, "SELinux fact restoration is not in always")
    require("_zabbix_integration_original_selinux_fact}, recursive=False)" in server,
            "SELinux fact restoration does not replace the complete saved subfact")
    require("selinux-policy-epel" not in server.replace(
        "# community.zabbix 4.3.0 asks for the nonexistent selinux-policy-epel on EL10.\n", ""),
        "wrapper attempts to install the nonexistent EL10 package")

    # The agent repeats the same defect after package/configuration mutations.
    # Its scoped bypass must restore the complete fact on success or failure,
    # leave enforcement unchanged, and skip both the package and sudo boolean.
    for token in ("_zabbix_integration_original_agent_selinux_fact",
                  "status': 'disabled'", "always:",
                  "ansible_facts.selinux.status == 'enabled'", "command: getenforce"):
        require(token in agent, f"missing scoped agent SELinux workaround contract: {token}")
    require(agent.count("command: getenforce") == 2,
            "enforcing mode is not checked around the agent workaround")
    agent_enforcing_before = agent.index("Verify SELinux remains enforcing before")
    agent_save = agent.index("Save the real SELinux fact for the agent role")
    agent_hide = agent.index("Temporarily hide SELinux from the agent role")
    include_agent = agent.index("Configure Zabbix Agent 2 without API mutations")
    agent_restore = agent.index("Restore the real SELinux fact after the agent role")
    agent_restored_assert = agent.index("Verify the agent SELinux fact was restored")
    agent_enforcing_after = agent.index("Verify SELinux remains enforcing after")
    require(agent_enforcing_before < agent_save < agent_hide < include_agent < agent_restore <
            agent_restored_assert < agent_enforcing_after,
            "scoped agent SELinux workaround ordering changed")
    require(agent.index("always:") < agent_restore,
            "agent SELinux fact restoration is not in always")
    require("_zabbix_integration_original_agent_selinux_fact}, recursive=False)" in agent,
            "agent SELinux restoration does not replace the complete saved subfact")
    require("selinux-policy-epel" not in agent.replace(
        "# community.zabbix 4.3.0 asks for the nonexistent selinux-policy-epel on EL10.\n", ""),
        "agent wrapper attempts to install the nonexistent EL10 package")
    require("zabbix_run_sudo" not in agent and "selinux_allow_zabbix_run_sudo" not in agent,
            "agent wrapper unnecessarily owns the upstream sudo SELinux boolean")


def agent_listener_contract_harness() -> None:
    """Evaluate the exact Ansible/Jinja listener contract against ss fixtures."""
    ansible = shutil.which("ansible-playbook")
    if not ansible:
        print("SKIP Agent 2 listener harness: ansible-playbook is not installed")
        return
    valid = ('LISTEN 0 4096 127.0.0.1:10050 0.0.0.0:* '
             'users:(("zabbix_agent2",pid=11782,fd=7))')
    invalid = (
        ['LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:(("zabbix_agent2",pid=1,fd=8))'],
        ['LISTEN 0 4096 [::]:9999 [::]:* users:(("zabbix_agent2",pid=1,fd=8))'],
        ['LISTEN 0 4096 1127.0.0.1:10050 0.0.0.0:* users:(("zabbix_agent2",pid=1,fd=7))'],
        ['LISTEN 0 4096 127.0.0.1:10051 0.0.0.0:* users:(("zabbix_agent2",pid=1,fd=7))'],
        ['LISTEN 0 4096 127.0.0.1:10050 0.0.0.0:* users:(("other",pid=1,fd=7))'],
        [valid, 'LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:(("zabbix_agent2",pid=1,fd=8))'],
        [valid, valid.replace('pid=11782', 'pid=2')],
    )
    assertion = """          - >-
            fixture |
            select('search', '\"zabbix_agent2\"') |
            select('match', '^LISTEN\\s+\\d+\\s+\\d+\\s+127\\.0\\.0\\.1:10050\\s+\\S+\\s+users:') |
            list | length == 1
          - >-
            fixture |
            select('search', '\"zabbix_agent2\"') | list | length == 1
"""
    with tempfile.TemporaryDirectory(prefix="zabbix-agent-listener-") as tmp:
        root = pathlib.Path(tmp)
        config = root / "ansible.cfg"
        config.write_text("[defaults]\nretry_files_enabled = False\n")
        env = os.environ.copy()
        env["ANSIBLE_CONFIG"] = str(config)

        def evaluate(name: str, fixture: list[str], should_pass: bool) -> None:
            play = root / f"{name}.yml"
            play.write_text(
                "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n"
                f"  vars:\n    fixture: {json.dumps(fixture)}\n"
                "  tasks:\n    - ansible.builtin.assert:\n        that:\n" + assertion)
            result = subprocess.run(
                [ansible, str(play), "-i", "localhost,"], cwd=root, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            require((result.returncode == 0) == should_pass,
                    f"Agent listener fixture {name} had unexpected result:\n{result.stdout}")

        evaluate("valid-exact-loopback", [valid], True)
        for index, fixture in enumerate(invalid):
            evaluate(f"invalid-{index}", fixture, False)



def harness() -> None:
    ansible = shutil.which("ansible-playbook")
    if not ansible:
        print("SKIP ansible syntax/validation: ansible-playbook is not installed")
        return
    with tempfile.TemporaryDirectory(prefix="zabbix-integration-harness-", dir=os.environ.get("TMPDIR")) as temp:
        root = pathlib.Path(temp)
        installed = root / "roles/tuxbull.zabbix_server"
        shutil.copytree(ROLE, installed)
        (root / "ansible.cfg").write_text("[defaults]\nroles_path = roles\nretry_files_enabled = False\n")
        env = os.environ.copy()
        env["ANSIBLE_CONFIG"] = str(root / "ansible.cfg")
        env["ANSIBLE_ROLES_PATH"] = str(root / "roles")
        env["PWD"] = str(root)
        playbook = installed / "tests/test.yml"
        subprocess.run([ansible, str(playbook), "-i", "localhost,", "--syntax-check"],
                       cwd=root, env=env, check=True)
        subprocess.run([ansible, str(playbook), "-i", "localhost,"], cwd=root, env=env, check=True)

        # Render and evaluate the complete live lifecycle expression. Unlike a
        # source-token check, this fails if any variable in the true branch is
        # misspelled or omitted from the realistic published-state fixture.
        prerequisites = text("tasks/Rocky-10/10_prerequisites.yml")
        expression_match = re.search(
            r"(?m)^    _zabbix_integration_frontend_secured: >-\n"
            r"(?P<body>(?:      .*\n)+)", prerequisites)
        require(expression_match is not None,
                "published lifecycle expression could not be extracted for execution")
        expression = "\n".join(
            line[6:] for line in expression_match.group("body").splitlines())
        rendered_expression = "\n".join(f"          {line}" for line in expression.splitlines())
        lifecycle_play = root / "published-lifecycle-expression.yml"
        lifecycle_play.write_text(
            "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n"
            "  vars:\n"
            "    zabbix_integration_publish: true\n"
            "    zabbix_integration_publish_server_name: zabbix.example.test\n"
            "    zabbix_integration_publish_listen_ipv4: 192.0.2.10\n"
            "    zabbix_integration_publish_certificate_path: /etc/pki/tls/zabbix-integration/server.crt\n"
            "    zabbix_integration_publish_private_key_path: /etc/pki/tls/zabbix-integration/server.key\n"
            "    _zabbix_integration_frontend_marker_matches_request: true\n"
            "    _zabbix_integration_prepackage_nginx_validation: {rc: 0}\n"
            "    _zabbix_integration_certificate_owned: true\n"
            "    _zabbix_integration_certificate_stat: {isreg: true, pw_name: root, gr_name: root, mode: '0644'}\n"
            "    _zabbix_integration_private_key_stat: {isreg: true, pw_name: root, gr_name: root, mode: '0600'}\n"
            "    _zabbix_integration_prepackage_https_validation:\n"
            "      rc: 0\n"
            "      stdout: '{\"fingerprint\":\"AA:BB\",\"served_fingerprint\":\"AA:BB\"}'\n"
            "    _zabbix_integration_certificate_marker_text: |\n"
            "      https-certificate-v2|zabbix.example.test|192.0.2.10|/etc/pki/tls/zabbix-integration/server.crt|/etc/pki/tls/zabbix-integration/server.key|AA:BB\n"
            "    _zabbix_integration_frontend_marker_text: |\n"
            "      https-published-v2|true|192.0.2.10|zabbix.example.test|/etc/pki/tls/zabbix-integration/server.crt|/etc/pki/tls/zabbix-integration/server.key|AA:BB\n"
            "    _zabbix_integration_prepackage_listeners:\n"
            "      stdout_lines:\n"
            "        - 'LISTEN 0 511 192.0.2.10:443 0.0.0.0:* users:((\"nginx\",pid=100,fd=6))'\n"
            "        - 'LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:((\"nginx\",pid=100,fd=7))'\n"
            "  tasks:\n"
            "    - name: Prove actual-newline markers equal their expected one-line values\n"
            "      ansible.builtin.assert:\n"
            "        that:\n"
            "          - (_zabbix_integration_certificate_marker_text | trim) == 'https-certificate-v2|zabbix.example.test|192.0.2.10|/etc/pki/tls/zabbix-integration/server.crt|/etc/pki/tls/zabbix-integration/server.key|AA:BB'\n"
            "          - (_zabbix_integration_frontend_marker_text | trim) == 'https-published-v2|true|192.0.2.10|zabbix.example.test|/etc/pki/tls/zabbix-integration/server.crt|/etc/pki/tls/zabbix-integration/server.key|AA:BB'\n"
            "    - name: Evaluate realistic valid published lifecycle\n"
            "      ansible.builtin.set_fact:\n"
            "        _published_lifecycle_result: >-\n" + rendered_expression + "\n"
            "    - ansible.builtin.assert:\n"
            "        that: _published_lifecycle_result | bool\n"
            "    - name: Make the published state invalid\n"
            "      ansible.builtin.set_fact:\n"
            "        _zabbix_integration_prepackage_https_validation:\n"
            "          rc: 1\n"
            "          stdout: '{\"fingerprint\":\"AA:BB\",\"served_fingerprint\":\"AA:BB\"}'\n"
            "    - name: Evaluate realistic invalid published lifecycle\n"
            "      ansible.builtin.set_fact:\n"
            "        _published_lifecycle_result: >-\n" + rendered_expression + "\n"
            "    - ansible.builtin.assert:\n"
            "        that: not (_published_lifecycle_result | bool)\n"
        )
        subprocess.run([ansible, str(lifecycle_play), "-i", "localhost,"], cwd=root,
                       env=env, check=True)

        # Prove include_role apply:no_log suppresses output from every included task.
        secret_role = root / "roles/secret_probe/tasks"
        secret_role.mkdir(parents=True)
        (secret_role / "main.yml").write_text(
            "---\n- name: Included secret probe\n  ansible.builtin.debug:\n    msg: '{{ probe_secret }}'\n"
        )
        secret_play = root / "secret.yml"
        secret_play.write_text(
            "---\n- hosts: localhost\n  gather_facts: false\n  tasks:\n"
            "    - ansible.builtin.include_role:\n        name: secret_probe\n"
            "        apply:\n          no_log: true\n          diff: false\n"
            "      vars:\n        probe_secret: NEVER_PRINT_THIS_SECRET\n"
        )
        secret = subprocess.run([ansible, str(secret_play), "-i", "localhost,", "-vvv"],
                                cwd=root, env=env, check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        require("NEVER_PRINT_THIS_SECRET" not in secret.stdout,
                "include_role apply:no_log leaked the synthetic secret")

        # Use a real capture proxy and empty NO_PROXY. The positive control
        # proves this local Ansible harness honors proxy variables when enabled.
        proxy_requests = []

        class HostileProxyFixture(http.server.BaseHTTPRequestHandler):
            def _capture(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode(
                    errors="replace"
                )
                proxy_requests.append({"method": self.command, "path": self.path,
                                       "headers": dict(self.headers), "body": body})
                self.send_response(418)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = _capture
            do_POST = _capture

            def log_message(self, _format, *_args):
                return

        proxy_fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HostileProxyFixture)
        proxy_thread = threading.Thread(target=proxy_fixture.serve_forever, daemon=True)
        proxy_thread.start()
        hostile_env = env.copy()
        hostile_proxy = f"http://127.0.0.1:{proxy_fixture.server_port}"
        for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                           "http_proxy", "https_proxy", "all_proxy"):
            hostile_env[proxy_name] = hostile_proxy
        hostile_env["NO_PROXY"] = ""
        hostile_env["no_proxy"] = ""
        proxy_probe = root / "proxy-probe.yml"
        proxy_probe.write_text(
            "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n"
            "  tasks:\n    - ansible.builtin.uri:\n"
            "        url: http://127.0.0.1:9/proxy-positive-control\n"
            "        use_proxy: true\n        status_code: 418\n"
        )
        subprocess.run([ansible, str(proxy_probe), "-i", "localhost,"], cwd=root,
                       env=hostile_env, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
        require(len(proxy_requests) == 1 and
                proxy_requests[0]["path"] == "http://127.0.0.1:9/proxy-positive-control",
                f"hostile proxy positive control was not captured: {proxy_requests!r}")
        proxy_control_count = len(proxy_requests)

        # Exercise stage 65's idempotent desired-password path against a real
        # loopback JSON-RPC HTTP server. The fixture rejects every unexpected
        # method, credential, token, or request order.
        api_requests = []
        desired_secret = "SYNTHETIC_DESIRED_ADMIN_SECRET_123"
        desired_token = "SYNTHETIC_SESSION_TOKEN_456"

        class ZabbixFixture(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                api_requests.append(request)
                response = {"jsonrpc": "2.0", "id": request["id"]}
                if request["method"] == "user.login" and request["params"] == {
                        "username": "Admin", "password": desired_secret, "userData": True}:
                    response["result"] = {
                        "sessionid": desired_token, "userid": "42", "username": "Admin"
                    }
                elif (request["method"] == "user.get" and
                      self.headers.get("Authorization") == f"Bearer {desired_token}" and
                      request["params"] == {
                          "output": ["userid", "username"], "filter": {"username": "Admin"}
                      }):
                    response["result"] = [{"userid": "42", "username": "Admin"}]
                else:
                    response["error"] = {"code": -32602, "message": "fixture rejected request"}
                encoded = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format, *_args):
                return

        server_fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ZabbixFixture)
        fixture_thread = threading.Thread(target=server_fixture.serve_forever, daemon=True)
        fixture_thread.start()
        try:
            synthetic_stage = root / "synthetic-65.yml"
            synthetic_state = root / "state"
            synthetic_stage.write_text(text("tasks/Rocky-10/65_admin_bootstrap.yml").replace(
                "http://127.0.0.1:8080", f"http://127.0.0.1:{server_fixture.server_port}"
            ).replace("/var/lib/zabbix-integration", str(synthetic_state)).replace(
                "become: true", "become: false"
            ).replace("owner: root", f"owner: {TEST_OWNER}").replace(
                "group: root", f"group: {TEST_GROUP}"))
            bootstrap_play = root / "bootstrap-desired.yml"
            bootstrap_play.write_text(
                "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n"
                "  vars:\n    zabbix_integration_admin_bootstrap: true\n"
                f'    zabbix_integration_admin_password: "{desired_secret}"\n'
                "  tasks:\n    - ansible.builtin.include_tasks: synthetic-65.yml\n"
            )
            first_bootstrap = subprocess.run(
                [ansible, str(bootstrap_play), "-i", "localhost,", "-vvv"], cwd=root,
                env=hostile_env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            require(first_bootstrap.returncode == 0,
                    f"synthetic desired bootstrap failed:\n{first_bootstrap.stdout}")
            second_bootstrap = subprocess.run(
                [ansible, str(bootstrap_play), "-i", "localhost,", "-vvv"], cwd=root,
                env=hostile_env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            require(second_bootstrap.returncode == 0,
                    f"synthetic desired bootstrap rerun failed:\n{second_bootstrap.stdout}")
        finally:
            server_fixture.shutdown()
            server_fixture.server_close()
            fixture_thread.join()
        combined_bootstrap_output = first_bootstrap.stdout + second_bootstrap.stdout
        require(desired_secret not in combined_bootstrap_output and
                desired_token not in combined_bootstrap_output,
                "stage 65 leaked a synthetic password or nested API token")
        require("changed=0" in second_bootstrap.stdout,
                "desired-password bootstrap rerun was not idempotent")
        require(len(api_requests) == 4 and
                [request["method"] for request in api_requests] ==
                ["user.login", "user.get", "user.login", "user.get"],
                f"desired-password path made unexpected API requests: {api_requests!r}")
        require(len(proxy_requests) == proxy_control_count,
                f"desired-password API calls reached the hostile proxy: {proxy_requests!r}")
        require(all(secret not in json.dumps(proxy_requests) for secret in
                    (desired_secret, desired_token)),
                "desired-path password or token reached the hostile proxy")
        marker_path = synthetic_state / "admin-api-bootstrap"
        require(marker_path.read_text() == "admin-api-bootstrap-v1\n" and
                marker_path.stat().st_mode & 0o777 == 0o600 and
                synthetic_state.stat().st_mode & 0o777 == 0o700,
                "verified synthetic Admin marker/state modes are wrong")

        # Exercise the vendor-default rotation path independently. The fixture
        # requires userData identities, current_passwd, sessionid bearer use,
        # and final filtered identity verification.
        rotation_requests = []
        default_token = "SYNTHETIC_DEFAULT_SESSION_789"
        rotated_token = "SYNTHETIC_ROTATED_SESSION_987"

        class ZabbixRotationFixture(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                rotation_requests.append(request)
                response = {"jsonrpc": "2.0", "id": request["id"]}
                params = request["params"]
                auth = self.headers.get("Authorization")
                if request["method"] == "user.login" and params == {
                        "username": "Admin", "password": desired_secret, "userData": True}:
                    if any(item["method"] == "user.update" for item in rotation_requests):
                        response["result"] = {
                            "sessionid": rotated_token, "userid": "42", "username": "Admin"
                        }
                    else:
                        response["error"] = {"code": -32602, "message": "desired credential not active"}
                elif request["method"] == "user.login" and params == {
                        "username": "Admin", "password": "zabbix", "userData": True}:
                    response["result"] = {
                        "sessionid": default_token, "userid": "42", "username": "Admin"
                    }
                elif (request["method"] == "user.update" and
                      auth == f"Bearer {default_token}" and params == {
                          "userid": "42", "current_passwd": "zabbix", "passwd": desired_secret
                      }):
                    response["result"] = {"userids": ["42"]}
                elif (request["method"] == "user.get" and
                      auth == f"Bearer {rotated_token}" and params == {
                          "output": ["userid", "username"], "filter": {"username": "Admin"}
                      }):
                    response["result"] = [{"userid": "42", "username": "Admin"}]
                else:
                    response["error"] = {"code": -32602, "message": "fixture rejected request"}
                encoded = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format, *_args):
                return

        rotation_fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ZabbixRotationFixture)
        rotation_thread = threading.Thread(target=rotation_fixture.serve_forever, daemon=True)
        rotation_thread.start()
        try:
            rotation_stage = root / "synthetic-65-rotation.yml"
            rotation_state = root / "rotation-state"
            rotation_stage.write_text(text("tasks/Rocky-10/65_admin_bootstrap.yml").replace(
                "http://127.0.0.1:8080", f"http://127.0.0.1:{rotation_fixture.server_port}"
            ).replace("/var/lib/zabbix-integration", str(rotation_state)).replace(
                "become: true", "become: false"
            ).replace("owner: root", f"owner: {TEST_OWNER}").replace(
                "group: root", f"group: {TEST_GROUP}"))
            rotation_play = root / "bootstrap-rotation.yml"
            rotation_play.write_text(
                "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n"
                "  vars:\n    zabbix_integration_admin_bootstrap: true\n"
                f'    zabbix_integration_admin_password: "{desired_secret}"\n'
                "  tasks:\n    - ansible.builtin.include_tasks: synthetic-65-rotation.yml\n"
            )
            rotation_run = subprocess.run(
                [ansible, str(rotation_play), "-i", "localhost,", "-vvv"], cwd=root,
                env=hostile_env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            require(rotation_run.returncode == 0,
                    f"synthetic rotation bootstrap failed:\n{rotation_run.stdout}")
        finally:
            rotation_fixture.shutdown()
            rotation_fixture.server_close()
            rotation_thread.join()
            proxy_fixture.shutdown()
            proxy_fixture.server_close()
            proxy_thread.join()
        require(desired_secret not in rotation_run.stdout and
                default_token not in rotation_run.stdout and rotated_token not in rotation_run.stdout,
                "rotation path leaked a synthetic password or session token")
        require([request["method"] for request in rotation_requests] ==
                ["user.login", "user.login", "user.update", "user.login", "user.get"],
                f"rotation path made unexpected API requests: {rotation_requests!r}")
        require(len(proxy_requests) == proxy_control_count,
                f"rotation API calls reached the hostile proxy: {proxy_requests!r}")
        require(all(secret not in json.dumps(proxy_requests) for secret in
                    (desired_secret, default_token, rotated_token)),
                "rotation password or token reached the hostile proxy")
        rotation_marker = rotation_state / "admin-api-bootstrap"
        require(rotation_marker.read_text() == "admin-api-bootstrap-v1\n" and
                rotation_marker.stat().st_mode & 0o777 == 0o600 and
                rotation_state.stat().st_mode & 0o777 == 0o700,
                "rotation path marker/state modes are wrong")

        # Model the agent workaround's exact nonrecursive restoration: an
        # upstream-added nested SELinux key must be removed, unrelated facts
        # survive, and the original agent-role failure must still propagate.
        selinux_restore_play = root / "agent-selinux-restore.yml"
        selinux_restore_play.write_text(
            "---\n- hosts: localhost\n  gather_facts: false\n  tasks:\n"
            "    - ansible.builtin.set_fact:\n"
            "        ansible_facts:\n"
            "          retained_fact: retained\n"
            "          selinux:\n"
            "            status: enabled\n"
            "            config_mode: enforcing\n"
            "    - block:\n"
            "        - block:\n"
            "            - ansible.builtin.set_fact:\n"
            "                original_selinux: '{{ ansible_facts.selinux | combine({}) }}'\n"
            "            - ansible.builtin.set_fact:\n"
            "                ansible_facts: >-\n"
            "                  {{ ansible_facts | combine({'selinux': ansible_facts.selinux |\n"
            "                  combine({'status': 'disabled', 'upstream_nested': {'leaked': true}},\n"
            "                  recursive=True)}, recursive=True) }}\n"
            "            - ansible.builtin.fail:\n"
            "                msg: synthetic upstream failure\n"
            "          always:\n"
            "            - ansible.builtin.set_fact:\n"
            "                ansible_facts: >-\n"
            "                  {{ ansible_facts | combine({'selinux': original_selinux},\n"
            "                  recursive=False) }}\n"
            "      rescue:\n"
            "        - ansible.builtin.assert:\n"
            "            that:\n"
            "              - ansible_facts.selinux == original_selinux\n"
            "              - ansible_facts.retained_fact == 'retained'\n"
            "              - ansible_facts.selinux.upstream_nested is not defined\n"
            "        - ansible.builtin.set_fact:\n"
            "            upstream_failure_propagated: true\n"
            "    - ansible.builtin.assert:\n"
            "        that: upstream_failure_propagated | default(false)\n"
        )
        subprocess.run([ansible, str(selinux_restore_play), "-i", "localhost,"],
                       cwd=root, env=env, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)

        # Execute the same single-backslash regexes through Ansible/Jinja filters
        # against realistic process-owning ss output, including balanced users
        # parentheses, wildcard sockets, and a non-nginx owner.
        listener_filters = root / "listener-filters.yml"
        listener_filters.write_text(
            "---\n- hosts: localhost\n  gather_facts: false\n  vars:\n"
            "    requested_ip: 192.0.2.10\n"
            "    listener_lines:\n"
            "      - 'LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:((\"nginx\",pid=123,fd=6),(\"nginx\",pid=122,fd=6))'\n"
            "      - 'LISTEN 0 511 192.0.2.10:443 0.0.0.0:* users:((\"nginx\",pid=123,fd=7),(\"nginx\",pid=122,fd=7))'\n"
            "      - 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=123,fd=8))'\n"
            "      - 'LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=123,fd=9))'\n"
            "      - 'LISTEN 0 511 192.0.2.10:443 0.0.0.0:* users:((\"caddy\",pid=321,fd=7))'\n"
            "  tasks:\n"
            "    - ansible.builtin.assert:\n"
            "        that:\n"
            "          - listener_lines | select('match', '^LISTEN\\s+\\d+\\s+\\d+\\s+127\\.0\\.0\\.1:8080\\s+.*users:\\(\\(\"nginx\",') | list | length == 1\n"
            "          - listener_lines | select('match', '^LISTEN\\s+\\d+\\s+\\d+\\s+' ~ (requested_ip | regex_escape) ~ ':443\\s+.*users:\\(\\(\"nginx\",') | list | length == 1\n"
            "          - listener_lines | select('search', ':443\\s') | list | length == 4\n"
        )
        subprocess.run([ansible, str(listener_filters), "-i", "localhost,"],
                       cwd=root, env=env, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)

        # Normal check mode must fail at the explicit pre-mutation gate.
        check_play = root / "check.yml"
        check_play.write_text(playbook.read_text().replace(
            "    zabbix_integration_validation_only: true\n", ""))
        check = subprocess.run([ansible, str(check_play), "-i", "localhost,", "--check"],
                               cwd=root, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        require(check.returncode != 0, "normal check mode was not rejected")
        require("does not support reliable check mode" in check.stdout,
                "check-mode failure was not actionable")

        # Every independently supplied release suffix rejects malformed input.
        for component in ("server", "web", "agent"):
            bad_play = root / f"bad-{component}-release.yml"
            bad_play.write_text(playbook.read_text().replace(
                f'zabbix_integration_{component}_release: "21-release1.el10"',
                f'zabbix_integration_{component}_release: "21-release1.el10; id"'))
            bad = subprocess.run([ansible, str(bad_play), "-i", "localhost,"],
                                 cwd=root, env=env, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            require(bad.returncode != 0, f"unsafe {component} release suffix passed validation")

        agent_override = root / "bad-agent-server.yml"
        agent_override.write_text(playbook.read_text().replace(
            "    zabbix_integration_validation_only: true\n",
            "    zabbix_integration_agent_server: 0.0.0.0\n"
            "    zabbix_integration_validation_only: true\n"))
        bad_agent = subprocess.run([ansible, str(agent_override), "-i", "localhost,"], cwd=root,
                                   env=env, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        require(bad_agent.returncode != 0, "non-loopback agent server passed validation")

        # Publication requires bootstrap and strict exact IPv4/FQDN inputs.
        publish_without_bootstrap = root / "publish-without-bootstrap.yml"
        publish_without_bootstrap.write_text(playbook.read_text().replace(
            "    zabbix_integration_validation_only: true\n",
            "    zabbix_integration_publish: true\n"
            "    zabbix_integration_publish_listen_ipv4: 192.0.2.10\n"
            "    zabbix_integration_publish_server_name: zabbix.example.test\n"
            "    zabbix_integration_validation_only: true\n"))
        publish_result = subprocess.run(
            [ansible, str(publish_without_bootstrap), "-i", "localhost,"], cwd=root,
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        require(publish_result.returncode != 0,
                "publication without Admin bootstrap passed validation")

        valid_publish = root / "valid-publish.yml"
        valid_publish.write_text(playbook.read_text().replace(
            "    zabbix_integration_admin_bootstrap: false\n",
            "    zabbix_integration_admin_bootstrap: true\n"
            "    zabbix_integration_publish: true\n"
            "    zabbix_integration_publish_listen_ipv4: 192.0.2.10\n"
            "    zabbix_integration_publish_server_name: zabbix.example.test\n"))
        subprocess.run([ansible, str(valid_publish), "-i", "localhost,"], cwd=root,
                       env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        for index, (address, fqdn) in enumerate((
                ("0.0.0.0/0", "zabbix.example.test"),
                ("0.0.0.0", "zabbix.example.test"),
                ("2001:db8::1", "zabbix.example.test"),
                ("999.2.3.4", "zabbix.example.test"),
                ("192.0.2.10", "localhost"),
                ("192.0.2.10", "bad_name.example.test"))):
            invalid_publish = root / f"invalid-publish-{index}.yml"
            invalid_publish.write_text(playbook.read_text().replace(
                "    zabbix_integration_admin_bootstrap: false\n",
                "    zabbix_integration_admin_bootstrap: true\n"
                "    zabbix_integration_publish: true\n"
                f"    zabbix_integration_publish_listen_ipv4: {address}\n"
                f"    zabbix_integration_publish_server_name: {fqdn}\n"))
            invalid_result = subprocess.run(
                [ansible, str(invalid_publish), "-i", "localhost,"], cwd=root,
                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            require(invalid_result.returncode != 0,
                    f"unsafe publication identity passed validation: {address}, {fqdn}")

        equal_paths = root / "invalid-equal-tls-paths.yml"
        equal_paths.write_text(playbook.read_text().replace(
            "    zabbix_integration_admin_bootstrap: false\n",
            "    zabbix_integration_admin_bootstrap: true\n"
            "    zabbix_integration_publish: true\n"
            "    zabbix_integration_publish_listen_ipv4: 192.0.2.10\n"
            "    zabbix_integration_publish_server_name: zabbix.example.test\n"
            "    zabbix_integration_publish_certificate_path: /etc/pki/tls/zabbix-integration/same.pem\n"
            "    zabbix_integration_publish_private_key_path: /etc/pki/tls/zabbix-integration/same.pem\n"))
        equal_result = subprocess.run(
            [ansible, str(equal_paths), "-i", "localhost,"], cwd=root, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        require(equal_result.returncode != 0, "equal normalized certificate/key paths passed validation")

        hostile_tls_paths = (
            ("/etc/pki/tls/../../../root", "/etc/pki/tls/zabbix-integration/server.crt",
             "/etc/pki/tls/zabbix-integration/server.key"),
            ("/etc/pki/tls/./zabbix-integration", "/etc/pki/tls/./zabbix-integration/server.crt",
             "/etc/pki/tls/./zabbix-integration/server.key"),
            ("/etc/pki/tls//zabbix-integration", "/etc/pki/tls//zabbix-integration/server.crt",
             "/etc/pki/tls//zabbix-integration/server.key"),
            ("/etc/pki/tls-sibling/zabbix-integration",
             "/etc/pki/tls-sibling/zabbix-integration/server.crt",
             "/etc/pki/tls-sibling/zabbix-integration/server.key"),
        )
        for index, (directory, cert, key) in enumerate(hostile_tls_paths):
            hostile_path_play = root / f"invalid-tls-path-{index}.yml"
            hostile_path_play.write_text(playbook.read_text().replace(
                "    zabbix_integration_admin_bootstrap: false\n",
                "    zabbix_integration_admin_bootstrap: true\n"
                "    zabbix_integration_publish: true\n"
                "    zabbix_integration_publish_listen_ipv4: 192.0.2.10\n"
                "    zabbix_integration_publish_server_name: zabbix.example.test\n"
                f"    zabbix_integration_publish_tls_directory: '{directory}'\n"
                f"    zabbix_integration_publish_certificate_path: '{cert}'\n"
                f"    zabbix_integration_publish_private_key_path: '{key}'\n"))
            hostile_path_result = subprocess.run(
                [ansible, str(hostile_path_play), "-i", "localhost,"], cwd=root, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            require(hostile_path_result.returncode != 0,
                    f"noncanonical TLS path passed validation: {directory!r}")

        for index, timezone in enumerate(("UTC", "Europe/Zurich", "Etc/GMT+1",
                                          "America/Argentina/Buenos_Aires")):
            timezone_play = root / f"good-timezone-{index}.yml"
            timezone_play.write_text(playbook.read_text().replace(
                "    zabbix_integration_validation_only: true\n",
                f'    zabbix_integration_timezone: "{timezone}"\n'
                "    zabbix_integration_validation_only: true\n"))
            subprocess.run([ansible, str(timezone_play), "-i", "localhost,"], cwd=root,
                           env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        bad_timezone = root / "bad-timezone.yml"
        bad_timezone.write_text(playbook.read_text().replace(
            "    zabbix_integration_validation_only: true\n",
            '    zabbix_integration_timezone: "Europe/Zurich\\nUTC"\n'
            "    zabbix_integration_validation_only: true\n"))
        timezone_result = subprocess.run([ansible, str(bad_timezone), "-i", "localhost,"], cwd=root,
                                         env=env, text=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT)
        require(timezone_result.returncode != 0, "timezone containing a newline passed validation")

        # Quotes, backslashes, dollars and controls cannot reach single-quoted PHP.
        for index, unsafe in enumerate(("quote'xxxxxxxxxxxxxxxxxxxx", r"slash\\xxxxxxxxxxxxxxxxxxxx",
                                        "$dollarxxxxxxxxxxxxxxxxxxxx", "line\\nxxxxxxxxxxxxxxxxxxxx")):
            unsafe_play = root / f"bad-secret-{index}.yml"
            unsafe_play.write_text(playbook.read_text().replace(
                "controller_only-placeholder-123", unsafe, 1))
            result = subprocess.run([ansible, str(unsafe_play), "-i", "localhost,"], cwd=root, env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            require(result.returncode != 0, f"unsafe secret passed validation: {unsafe!r}")


if __name__ == "__main__":
    contracts()
    print("PASS static contracts")
    agent_listener_contract_harness()
    print("PASS Agent 2 listener contract harness")
    subprocess.run(["python3", str(ROLE / "tests/schema_lifecycle/run.py")], check=True)
    print("PASS executable PostgreSQL schema lifecycle harness")
    harness()
    print("PASS controller-only harness")
