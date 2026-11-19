#!/usr/bin/env python3
"""Execute production schema lifecycle tasks against stateful module/process fakes."""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROLE = HERE.parents[1]
SECRET = "SYNTHETIC_SCHEMA_SECRET_NEVER_PRINT"

CASES = (
    dict(name="missing-unit-install-order", database_exists=True, schema_rows=None,
         unit_exists=False, active=False, masked=False, enabled=False, config="new",
         expect_success=True),
    dict(name="absent-database-exact-match", database_exists=False, schema_rows=None,
         unit_exists=False, active=False, masked=False, enabled=False, config="new",
         expect_success=True),
    dict(name="import-failure", database_exists=True, schema_rows=None,
         unit_exists=True, active=False, masked=False, enabled=False, config="new",
         import_failure=True, expect_success=False),
    dict(name="verification-failure", database_exists=True, schema_rows=None,
         unit_exists=True, active=False, masked=False, enabled=False, config="new",
         verify_failure=True, expect_success=False),
    dict(name="malformed-active-schema", database_exists=True, schema_rows=1,
         mandatory="malformed", unit_exists=True, active=True, masked=False,
         enabled=True, config="stable", package_installed_before=True,
         expect_success=False),
    dict(name="boolean-true-active-schema", database_exists=True, schema_rows=1,
         mandatory=True, unit_exists=True, active=True, masked=False,
         enabled=True, config="stable", package_installed_before=True,
         expect_success=False),
    dict(name="boolean-false-active-schema", database_exists=True, schema_rows=1,
         mandatory=False, unit_exists=True, active=True, masked=False,
         enabled=True, config="stable", package_installed_before=True,
         expect_success=False),
    dict(name="reused-state-recovery", database_exists=True, schema_rows=None,
         unit_exists=True, active=True, masked=False, enabled=True, config="new",
         expect_success=True),
    dict(name="active-stable", database_exists=True, schema_rows=1,
         unit_exists=True, active=True, masked=False, enabled=True, config="stable",
         package_installed_before=True, expect_success=True),
    dict(name="active-config-drift", database_exists=True, schema_rows=1,
         unit_exists=True, active=True, masked=False, enabled=True, config="new",
         package_installed_before=True, expect_success=True),
    dict(name="ready-stopped", database_exists=True, schema_rows=1,
         unit_exists=True, active=False, masked=False, enabled=True, config="stable",
         package_installed_before=True, expect_success=True),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_case(root: pathlib.Path, case: dict) -> None:
    case_root = root / case["name"]
    case_root.mkdir()
    config_path = case_root / "zabbix_server.conf"
    initial_content = "stable"
    config_path.write_text(initial_content)
    config_path.chmod(0o640)
    state = {
        "database_exists": case["database_exists"],
        "schema_rows": case["schema_rows"],
        "mandatory": case.get("mandatory", 8000000),
        "unit_exists": case["unit_exists"],
        "active": case["active"],
        "masked": case["masked"],
        "enabled": case["enabled"],
        "events": [],
        "import_failure": case.get("import_failure", False),
        "verify_failure": case.get("verify_failure", False),
        "package_installed_before": case.get("package_installed_before", False),
    }
    state_path = case_root / "state.json"
    state_path.write_text(json.dumps(state))
    env = os.environ.copy()
    env.update({
        "ANSIBLE_CONFIG": str(HERE / "ansible.cfg"),
        "ANSIBLE_COLLECTIONS_PATH": str(HERE / "collection"),
        "ANSIBLE_ROLES_PATH": str(root / "roles"),
        "LIFECYCLE_STATE": str(state_path),
        "LIFECYCLE_CONFIG_PATH": str(config_path),
        "LIFECYCLE_CONFIG_CONTENT": case["config"],
        "PATH": str(HERE / "bin") + os.pathsep + env["PATH"],
        "PWD": str(root),
    })
    result = subprocess.run(
        ["ansible-playbook", str(HERE / "playbook.yml"), "-i", "localhost,", "-vvv"],
        cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    require((result.returncode == 0) == case["expect_success"],
            f"{case['name']} unexpected rc={result.returncode}:\n{result.stdout}")
    require(SECRET not in result.stdout, f"{case['name']} leaked synthetic secret at -vvv")
    final = json.loads(state_path.read_text())
    events = final["events"]

    if case["name"] == "missing-unit-install-order":
        require(events.index("mask") < events.index("package") < events.index("import") < events.index("unmask"),
                f"missing unit lifecycle order unsafe: {events}")
    elif case["name"] == "absent-database-exact-match":
        require(events.index("mask") < events.index("package") < events.index("import") < events.index("unmask"),
                f"absent database lifecycle order unsafe: {events}")
        require(final["database_exists"] and final["active"] and not final["masked"],
                f"absent database was not created and released safely: {final}")
    elif case["name"] in ("import-failure", "verification-failure",
                          "malformed-active-schema", "boolean-true-active-schema",
                          "boolean-false-active-schema"):
        require(final["masked"] and not final["active"],
                f"{case['name']} did not fail closed: {final}")
        require("unmask" not in events and "start" not in events,
                f"{case['name']} released service: {events}")
        if case["name"] in ("malformed-active-schema", "boolean-true-active-schema",
                            "boolean-false-active-schema"):
            require(events.index("stop") < events.index("mask"),
                    f"malformed active schema was not stopped before masking: {events}")
    elif case["name"] == "reused-state-recovery":
        require(events.index("stop") < events.index("mask") < events.index("import") < events.index("unmask"),
                f"reused recovery order unsafe: {events}")
        require(final["active"] and not final["masked"], "reused state was not recovered")
    elif case["name"] == "active-stable":
        require(not any(x in events for x in ("mask", "unmask", "start", "stop", "restart", "enable", "disable")),
                f"stable active state mutated service: {events}")
        match = re.search(r"PLAY RECAP.*?changed=(\d+)", result.stdout, re.S)
        require(match is not None and match.group(1) == "0",
                f"stable active run was not changed=0:\n{result.stdout}")
    elif case["name"] == "active-config-drift":
        require(events.count("restart") == 1 and "stop" not in events and "mask" not in events,
                f"config drift did not produce exactly one restart: {events}")
    elif case["name"] == "ready-stopped":
        require(final["active"] and events.count("start") == 1 and "mask" not in events,
                f"ready stopped service was not started safely: {events}")
    print(f"PASS {case['name']}")


def main() -> None:
    for executable in (HERE / "bin/systemctl", HERE / "bin/sudo", HERE / "bin/psql"):
        executable.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="schema-lifecycle-", dir=os.environ.get("TMPDIR")) as tmp:
        root = pathlib.Path(tmp)
        installed = root / "roles/tuxbull.zabbix_server"
        shutil.copytree(ROLE, installed, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        for case in CASES:
            run_case(root, case)
    print("PASS true executable schema/service lifecycle harness")


if __name__ == "__main__":
    main()
