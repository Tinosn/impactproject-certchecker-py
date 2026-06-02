"""Minimal TLS cert checker — single file, drop into any project.

Usage:
    from certcheck import check_cert
    result = check_cert("example.com")         # or "example.com:8443"
    print(result["days_left"], result["ok"], result["issues"])
"""
from __future__ import annotations

import select
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import OpenSSL.SSL
import OpenSSL.crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

_WARN_DAYS = 30
_CRITICAL_DAYS = 7
_WEAK_SIG = frozenset({
    "md2WithRSAEncryption", "md5WithRSAEncryption",
    "sha1WithRSAEncryption", "sha1WithRSASignature", "ecdsa-with-SHA1",
})
_DEPRECATED_TLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def check_cert(target: str, timeout: float = 5.0) -> dict:
    """Return a dict with cert info and an issues list.

    result["ok"]     — False if any critical issue exists
    result["issues"] — list of {"level": "critical"|"warn"|"info", "msg": str}
    """
    host, port = _parse(target)
    chain, tls_version, cipher = _connect(host, port, timeout)

    leaf_ossl = chain[0]
    leaf = leaf_ossl.to_cryptography()
    not_after  = _asn1(leaf_ossl.get_notAfter())
    not_before = _asn1(leaf_ossl.get_notBefore())
    days_left  = (not_after - datetime.now(timezone.utc)).days
    subject    = {a.oid._name: a.value for a in leaf.subject}
    issuer     = {a.oid._name: a.value for a in leaf.issuer}
    sans       = _get_sans(leaf)
    is_self_signed = leaf.subject == leaf.issuer
    sig_alg    = leaf_ossl.get_signature_algorithm().decode()

    issues: list[dict] = []

    if days_left < 0:
        issues.append({"level": "critical", "msg": f"Expired {abs(days_left)} days ago"})
    elif days_left < _CRITICAL_DAYS:
        issues.append({"level": "critical", "msg": f"Expires in {days_left} days"})
    elif days_left < _WARN_DAYS:
        issues.append({"level": "warn", "msg": f"Expires in {days_left} days"})

    if is_self_signed:
        issues.append({"level": "critical", "msg": "Self-signed certificate"})

    if not _covers_host(host, sans, subject.get("commonName", "")):
        issues.append({"level": "critical", "msg": f"Hostname mismatch — cert does not cover {host!r}"})

    _key_issues(leaf.public_key(), issues)

    if sig_alg in _WEAK_SIG:
        issues.append({"level": "warn", "msg": f"Weak signature algorithm: {sig_alg}"})

    if tls_version in _DEPRECATED_TLS:
        issues.append({"level": "warn", "msg": f"Deprecated TLS version: {tls_version}"})

    if len(chain) == 1 and not is_self_signed:
        issues.append({"level": "warn", "msg": "Incomplete chain — no intermediates sent by server"})

    if any(s.startswith("DNS:*.") for s in sans) or subject.get("commonName", "").startswith("*."):
        issues.append({"level": "info", "msg": "Wildcard certificate"})

    return {
        "host": host,
        "port": port,
        "cn": subject.get("commonName", ""),
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "sans": sans,
        "tls_version": tls_version,
        "cipher": cipher,
        "is_self_signed": is_self_signed,
        "chain_length": len(chain),
        "issues": issues,
        "ok": not any(i["level"] == "critical" for i in issues),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse(raw: str) -> tuple[str, int]:
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname:
        raise ValueError(f"Cannot parse host from {raw!r}")
    return p.hostname, p.port or 443


def _connect(host: str, port: int, timeout: float):
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *_: True)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    conn = OpenSSL.SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(host.encode())
    conn.set_connect_state()
    deadline = time.monotonic() + timeout
    while True:
        try:
            conn.do_handshake()
            break
        except OpenSSL.SSL.WantReadError:
            _wait_sock(sock, readable=True, deadline=deadline)
        except OpenSSL.SSL.WantWriteError:
            _wait_sock(sock, readable=False, deadline=deadline)
    try:
        chain   = conn.get_peer_cert_chain() or []
        version = conn.get_protocol_version_name() or "Unknown"
        cipher  = conn.get_cipher_name() or "Unknown"
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        sock.close()
    return chain, version, cipher


def _wait_sock(sock: socket.socket, readable: bool, deadline: float) -> None:
    rem = deadline - time.monotonic()
    if rem <= 0:
        raise socket.timeout("TLS handshake timed out")
    if readable:
        select.select([sock], [], [], rem)
    else:
        select.select([], [sock], [], rem)


def _asn1(raw: bytes) -> datetime:
    return datetime.strptime(raw.decode(), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def _get_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return (
            [f"DNS:{d}" for d in ext.value.get_values_for_type(x509.DNSName)]
            + [f"IP:{i}" for i in ext.value.get_values_for_type(x509.IPAddress)]
        )
    except x509.ExtensionNotFound:
        return []


def _covers_host(host: str, sans: list[str], cn: str) -> bool:
    for entry in (sans or [f"DNS:{cn}"]):
        if entry.startswith("DNS:"):
            pat = entry[4:].lower()
            h = host.lower()
            if pat.startswith("*."):
                suf = pat[1:]
                if h.endswith(suf) and "." not in h[: -len(suf)]:
                    return True
            elif h == pat:
                return True
        elif entry.startswith("IP:") and host.lower() == entry[3:].lower():
            return True
    return False


def _key_issues(pub, issues: list[dict]) -> None:
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        issues.append({"level": "warn", "msg": f"Weak RSA key: {pub.key_size} bits (min 2048)"})
    elif isinstance(pub, ec.EllipticCurvePublicKey) and pub.key_size < 256:
        issues.append({"level": "warn", "msg": f"Weak EC key: {pub.key_size} bits (min 256)"})


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = check_cert(target)
    print(json.dumps(result, indent=2))
    sys.exit(2 if not result["ok"] else (1 if any(i["level"] == "warn" for i in result["issues"]) else 0))
