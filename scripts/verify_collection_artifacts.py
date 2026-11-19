#!/usr/bin/env python3
"""Download the complete pinned collection lock and verify hashes/dependencies."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile

EXPECTED = {
    "ansible-netcommon-8.4.0.tar.gz": "fafb603557bd4bb39aa40f56f3c3757d4a14d78259a57161c8f99db7fc81f33f",
    "ansible-posix-2.1.0.tar.gz": "5ff232cf69492a991f2a0990dbb23ef25a600b7e9209de6e33377a6ff08a8a29",
    "ansible-utils-6.0.1.tar.gz": "4fdd52d387fb4459ca5b80ce8b428f7a7173e40ad4106f24d7d74a8cd5aa04e9",
    "ansible-windows-3.3.0.tar.gz": "1d5793991e342dcbbcd8377e62e3f8443d39c3e625272118dae895ed43f5539c",
    "community-general-12.4.0.tar.gz": "c26b6f4b2d964bfe0b8c9eec53962324f3ed77777d915db5791d802a3fed247a",
    "community-mysql-4.1.0.tar.gz": "cc08dc63685ccc0fb4df0a3222cb14d59168941ca5215459805fd18149350643",
    "community-postgresql-4.2.0.tar.gz": "1507b58bb3ff391ed7d847fc3f2985be15667761621899d0d7bbf92aee66e30a",
    "community-windows-3.1.0.tar.gz": "9c3f950623e2d9777fc3167a0f893469be58620c4b8b9ef9e7556e5ccb28439a",
    "community-zabbix-4.3.0.tar.gz": "d30bbf022bc32bae89771f8d3611b31d9a524f5d384ff600067e7d0ba9480a5a",
    "containers-podman-1.19.0.tar.gz": "944c380094bcde001b510c22d8038ab9884eab3c7857aba21e2313fb79e7ed84",
    "fedora-linux_system_roles-2.5.0.tar.gz": "e5a485d0f06395f8dcf9fafe2267f3e8eb1d1aa27ec9b73162e4f8f84e53a046",
}
EXPECTED_DEPENDENCIES = {
    "ansible.netcommon": {"ansible.utils": ">=3.0.0"},
    "ansible.posix": {}, "ansible.utils": {}, "ansible.windows": {},
    "community.general": {}, "community.mysql": {}, "community.postgresql": {},
    "community.windows": {"ansible.windows": ">=3.0.0,<4.0.0"},
    "community.zabbix": {
        "ansible.windows": ">=2.8.0", "ansible.netcommon": ">=3.1.1",
        "ansible.posix": "*", "community.general": "*", "community.mysql": ">=3.10.0",
        "community.postgresql": "*", "community.windows": "*",
    },
    "containers.podman": {},
    "fedora.linux_system_roles": {
        "ansible.posix": "*", "community.general": "*", "containers.podman": "*",
    },
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scratch", type=pathlib.Path)
    args = parser.parse_args()
    args.scratch.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "ansible-galaxy", "collection", "download", "-r", "requirements.yml",
        "-p", str(args.scratch), "--no-deps"
    ], check=True)
    artifacts = {path.name for path in args.scratch.glob("*.tar.gz")}
    if artifacts != set(EXPECTED):
        raise SystemExit(f"lock artifact set mismatch: {sorted(artifacts ^ set(EXPECTED))}")
    found_dependencies = {}
    for name, expected in EXPECTED.items():
        path = args.scratch / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {name}: {actual}")
        with tarfile.open(path, "r:gz") as archive:
            manifest = json.load(archive.extractfile("MANIFEST.json"))
        info = manifest["collection_info"]
        collection = f"{info['namespace']}.{info['name']}"
        found_dependencies[collection] = info.get("dependencies", {})
        print(f"verified {name} {actual}")
    if found_dependencies != EXPECTED_DEPENDENCIES:
        raise SystemExit(f"dependency graph changed: {found_dependencies}")
    missing = set().union(*(deps.keys() for deps in found_dependencies.values())) - set(found_dependencies)
    if missing:
        raise SystemExit(f"dependency graph is not closed: {sorted(missing)}")
    print("verified exact transitive dependency graph closure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
