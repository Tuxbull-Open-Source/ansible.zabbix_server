#!/usr/bin/python3
"""Validate role-owned direct HTTPS material without printing key content."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys


def run(argv: list[str], *, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, timeout=15)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def output(command: list[str]) -> str:
    result = run(command)
    require(result.returncode == 0, "openssl validation command failed")
    return result.stdout.decode("utf-8", "strict").strip()


def public_key_digest(command: list[str]) -> str:
    result = run(command)
    require(result.returncode == 0, "public-key extraction failed")
    return hashlib.sha256(result.stdout).hexdigest()


def certificate_fingerprint(cert: str) -> str:
    value = output(["openssl", "x509", "-in", cert, "-noout", "-fingerprint", "-sha256"])
    require(value.startswith("sha256 Fingerprint=") or value.startswith("SHA256 Fingerprint="),
            "certificate fingerprint output malformed")
    return value.split("=", 1)[1].replace(":", "").lower()


def validate_directory_chain(directory: str, require_final: bool = False,
                             required_baseline: tuple[str, ...] =
                             ("/etc", "/etc/pki", "/etc/pki/tls"),
                             required_owner_uid: int | None = 0) -> dict[str, object]:
    """Validate existing path components without following symbolic links."""
    path = pathlib.Path(directory)
    require(path.is_absolute() and os.path.normpath(directory) == directory,
            "directory path must be canonical and absolute")
    components = [pathlib.Path("/")]
    current = pathlib.Path("/")
    for part in path.parts[1:]:
        current /= part
        components.append(current)

    existing: list[tuple[pathlib.Path, os.stat_result]] = []
    missing: list[str] = []
    missing_seen = False
    for component in components:
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            missing_seen = True
            missing.append(str(component))
            continue
        require(not missing_seen, "path component exists below a missing ancestor")
        require(not stat.S_ISLNK(metadata.st_mode),
                f"symbolic-link directory component rejected: {component}")
        require(stat.S_ISDIR(metadata.st_mode),
                f"non-directory path component rejected: {component}")
        existing.append((component, metadata))

    require(set(required_baseline) <= {str(component) for component, _metadata in existing},
            "required baseline directories must exist")
    for component, metadata in existing:
        if component == pathlib.Path("/"):
            continue
        require(required_owner_uid is None or metadata.st_uid == required_owner_uid,
                f"directory component has wrong owner: {component}")
        require(metadata.st_mode & 0o022 == 0,
                f"directory component is group/world writable: {component}")
    require(not require_final or not missing,
            "final directory does not exist as a real directory")
    return {"valid": True, "directory": directory, "exists": not missing,
            "missing_components": missing}


def validate_local(cert: str, key: str, dns: str, ip: str, checkend: int) -> str:
    cert_path = pathlib.Path(cert)
    key_path = pathlib.Path(key)
    cert_resolved = cert_path.resolve(strict=True)
    key_resolved = key_path.resolve(strict=True)
    require(cert_resolved == cert_path and key_resolved == key_path,
            "certificate and key paths must be canonical and may not be symlinks")
    require(cert_resolved != key_resolved,
            "certificate and key paths are identical")
    require(stat.S_ISREG(cert_path.lstat().st_mode) and stat.S_ISREG(key_path.lstat().st_mode),
            "certificate pair is incomplete or non-regular")
    require(ipaddress.ip_address(ip).version == 4 and ip != "0.0.0.0", "invalid IPv4 identity")

    checked = run(["openssl", "x509", "-in", cert, "-noout", "-checkend", str(checkend)])
    require(checked.returncode == 0, "certificate is expired or inside renewal window")

    identity = output(["openssl", "x509", "-in", cert, "-noout", "-subject", "-issuer",
                       "-nameopt", "RFC2253"]).splitlines()
    require(identity == [f"subject=CN={dns}", f"issuer=CN={dns}"],
            "certificate CN, subject, or issuer does not exactly match")

    verified = run(["openssl", "verify", "-check_ss_sig", "-CAfile", cert, cert])
    require(verified.returncode == 0, "certificate self-signature verification failed")

    san_text = output(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"])
    tokens: list[tuple[str, str]] = []
    for token in re.split(r",", " ".join(san_text.splitlines()[1:])):
        token = token.strip()
        if token.startswith("DNS:"):
            tokens.append(("DNS", token[4:].strip().lower()))
        elif token.startswith("IP Address:"):
            tokens.append(("IP", token[11:].strip()))
        elif token:
            tokens.append(("OTHER", token))
    require(tokens == [("DNS", dns.lower()), ("IP", str(ipaddress.ip_address(ip)))] or
            tokens == [("IP", str(ipaddress.ip_address(ip))), ("DNS", dns.lower())],
            "certificate SAN set is not exactly the requested DNS and IPv4 identity")

    cert_key = public_key_digest(["openssl", "x509", "-in", cert, "-noout", "-pubkey"])
    private_key = public_key_digest(["openssl", "pkey", "-in", key, "-pubout"])
    require(cert_key == private_key, "certificate and private key do not match")
    return certificate_fingerprint(cert)


def served_fingerprint(ip: str, dns: str) -> str:
    handshake = run(["openssl", "s_client", "-connect", f"{ip}:443", "-servername", dns,
                     "-showcerts"], data=b"")
    require(handshake.returncode == 0, "local TLS handshake failed")
    match = re.search(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", handshake.stdout,
                      flags=re.DOTALL)
    require(match is not None, "TLS peer did not provide a certificate")
    if match is None:  # Narrow the type for static checkers; require already raises.
        raise ValueError("TLS peer did not provide a certificate")
    parsed = run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], data=match.group(0))
    require(parsed.returncode == 0, "served certificate could not be parsed")
    value = parsed.stdout.decode("ascii", "strict").strip()
    require("=" in value, "served fingerprint output malformed")
    return value.split("=", 1)[1].replace(":", "").lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-directory-chain")
    parser.add_argument("--require-final-directory", action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--dns")
    parser.add_argument("--ip")
    parser.add_argument("--checkend", type=int)
    parser.add_argument("--served", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate_directory_chain is not None:
            require(not any((args.cert, args.key, args.dns, args.ip, args.checkend, args.served)),
                    "directory-chain validation cannot be combined with certificate validation")
            print(json.dumps(validate_directory_chain(args.validate_directory_chain,
                                                       args.require_final_directory),
                             sort_keys=True))
            return 0
        require(not args.require_final_directory,
                "--require-final-directory requires --validate-directory-chain")
        require(all(value is not None for value in
                    (args.cert, args.key, args.dns, args.ip, args.checkend)),
                "certificate validation requires --cert, --key, --dns, --ip, and --checkend")
        fingerprint = validate_local(args.cert, args.key, args.dns, args.ip, args.checkend)
        result: dict[str, object] = {"valid": True, "fingerprint": fingerprint}
        if args.served:
            peer = served_fingerprint(args.ip, args.dns)
            require(peer == fingerprint, "served certificate fingerprint differs from file")
            result["served_fingerprint"] = peer
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        print(json.dumps({"valid": False, "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
