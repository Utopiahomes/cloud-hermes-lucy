"""Run the Management Contract v1 seam across two independent local processes.

This is an explicit compatibility probe, not part of the ordinary unit suite. It
loads a separately checked-out Homes adapter only in the provider subprocess and
uses the real Control ``ManagementClient`` in this process. All TLS and JWT key
material is generated in a temporary directory and discarded when the probe ends.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lucy.management_contract import (
    MANAGEMENT_BUNDLE_DIGEST,
    verify_management_bundle,
)

EXPECTED_ADAPTER_COMMIT = "c04a97a47c9bbecb9e45b882492f756eeaaed196"
KEY_ID = "management-seam-probe"
RELEASE_ID = "homes-management:release:seam-proof.1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter-root", required=True, type=Path)
    parser.add_argument("--expected-adapter-commit", default=EXPECTED_ADAPTER_COMMIT)
    return parser.parse_args()


def _git(adapter_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={adapter_root}", "-C", str(adapter_root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _write_tls_material(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(UTC)
    ca_key = generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Stoin seam probe CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / "ca.pem"
    certificate_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, certificate_path, key_path


def _wait_for_port(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Homes adapter exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Homes adapter did not listen within 10 seconds")


def _adapter_environment(
    adapter_root: Path,
    port: int,
    jwt_private_key: Ed25519PrivateKey,
    certificate_path: Path,
    key_path: Path,
) -> dict[str, str]:
    public_pem = jwt_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(adapter_root / "src"),
            "PORT": str(port),
            "MANAGEMENT_ADAPTER_ENVIRONMENT": "test",
            "MANAGEMENT_ADAPTER_DISPLAY_NAME": "Utopia Homes Prime",
            "MANAGEMENT_ADAPTER_DEPLOYMENT_ID": (
                "stoin:deployment:utopia-homes-management:seam-proof"
            ),
            "MANAGEMENT_ADAPTER_RUNTIME_ID": (
                "stoin:runtime:utopia-homes-management:seam-proof"
            ),
            "MANAGEMENT_ADAPTER_RELEASE_ID": RELEASE_ID,
            "MANAGEMENT_ADAPTER_SOFTWARE_VERSION": "0.1.0",
            "MANAGEMENT_ADAPTER_ARTIFACT_DIGEST": f"sha256:{'0' * 64}",
            "MANAGEMENT_ADAPTER_DEPLOYED_AT": "2026-09-16T00:00:00Z",
            "MANAGEMENT_ADAPTER_CAPABILITIES_JSON": json.dumps(
                [
                    {
                        "capability_id": "guest.answer",
                        "contract_version": "1.0",
                        "state": "enabled",
                    }
                ]
            ),
            "MANAGEMENT_ADAPTER_JWT_PUBLIC_KEYS_JSON": json.dumps(
                [{"kid": KEY_ID, "public_key_pem": public_pem, "status": "active"}]
            ),
            "MANAGEMENT_ADAPTER_RATE_LIMIT_PER_MINUTE": "120",
            "MANAGEMENT_ADAPTER_LOG_LEVEL": "WARNING",
            "SEAM_TLS_CERTIFICATE": str(certificate_path),
            "SEAM_TLS_KEY": str(key_path),
        }
    )
    return environment


def _commission_environment(
    control_root: Path,
    port: int,
    jwt_private_key: Ed25519PrivateKey,
    ca_path: Path,
) -> dict[str, str]:
    private_seed = jwt_private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(control_root / "src"),
            "SSL_CERT_FILE": str(ca_path),
            "STOIN_MANAGEMENT_PROVIDER_BASE_URL": f"https://localhost:{port}",
            "STOIN_MANAGEMENT_EXPECTED_PROVIDER_RELEASE_ID": RELEASE_ID,
            "STOIN_MANAGEMENT_JWT_PRIVATE_KEY_B64": base64.b64encode(private_seed).decode(
                "ascii"
            ),
            "STOIN_MANAGEMENT_JWT_KEY_ID": KEY_ID,
        }
    )
    return environment


def main() -> None:
    arguments = _arguments()
    adapter_root = arguments.adapter_root.resolve()
    control_root = Path(__file__).resolve().parents[2]
    adapter_commit = _git(adapter_root, "rev-parse", "HEAD")
    if adapter_commit != arguments.expected_adapter_commit:
        raise RuntimeError("Homes adapter commit differs from the reviewed handoff")
    if _git(adapter_root, "status", "--porcelain"):
        raise RuntimeError("Homes adapter worktree is not clean")

    control_digest = verify_management_bundle()
    adapter_digest_path = adapter_root / "contracts/stoin-management-v1-bundle/DIGEST.txt"
    adapter_digest = adapter_digest_path.read_text(encoding="ascii").strip()
    if control_digest != MANAGEMENT_BUNDLE_DIGEST or adapter_digest != MANAGEMENT_BUNDLE_DIGEST:
        raise RuntimeError("Management Contract bundle pins differ")

    jwt_private_key = Ed25519PrivateKey.generate()
    port = _free_port()
    with tempfile.TemporaryDirectory(prefix="stoin-management-seam-") as temporary:
        temporary_path = Path(temporary)
        ca_path, certificate_path, key_path = _write_tls_material(temporary_path)
        launcher = (
            "import os, uvicorn; "
            "from management_adapter.api import create_app; "
            "from management_adapter.config import Config; "
            "uvicorn.run(create_app(config=Config.from_environment()), host='127.0.0.1', "
            "port=int(os.environ['PORT']), ssl_certfile=os.environ['SEAM_TLS_CERTIFICATE'], "
            "ssl_keyfile=os.environ['SEAM_TLS_KEY'], access_log=False, log_level='warning')"
        )
        environment = _adapter_environment(
            adapter_root, port, jwt_private_key, certificate_path, key_path
        )
        process = subprocess.Popen(
            [sys.executable, "-c", launcher],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_port(process, port)
            valid_environment = _commission_environment(
                control_root, port, jwt_private_key, ca_path
            )
            valid = subprocess.run(
                [sys.executable, "-m", "lucy.management_commission"],
                env=valid_environment,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if valid.returncode != 0 or valid.stderr:
                raise RuntimeError("Control commissioning command did not pass")
            evidence = json.loads(valid.stdout)
            expected = {
                "capability": evidence["enabled_capabilities"],
                "digest": evidence["bundle_digest"],
                "health": evidence["health_status"],
                "reason_codes": evidence["health_reason_codes"],
                "release": evidence["management_provider_release_id"],
                "resources": evidence["resources_observed"],
            }
            if expected != {
                "capability": ["guest.answer"],
                "digest": MANAGEMENT_BUNDLE_DIGEST,
                "health": "unknown",
                "reason_codes": ["health_coverage_limited"],
                "release": RELEASE_ID,
                "resources": 4,
            }:
                raise RuntimeError("Control commissioning evidence differs from RC3")

            invalid_environment = _commission_environment(
                control_root, port, Ed25519PrivateKey.generate(), ca_path
            )
            invalid = subprocess.run(
                [sys.executable, "-m", "lucy.management_commission"],
                env=invalid_environment,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if (
                invalid.returncode == 0
                or invalid.stdout
                or invalid.stderr != "management commissioning failed\n"
            ):
                raise RuntimeError("Invalid-signature commissioning did not fail closed")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    print(
        json.dumps(
            {
                "adapter_commit": adapter_commit,
                "bundle_digest": control_digest,
                "capability": "guest.answer",
                "health_status": "unknown",
                "invalid_signature": "rejected",
                "resources_observed": 4,
                "transport": "local-tls",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
