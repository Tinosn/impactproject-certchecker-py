# certchecker-py

A minimal TLS/SSL certificate checker — single file, drop into any Python project.

## Features

- Expiry checking with configurable warn/critical thresholds
- Self-signed certificate detection
- Hostname/SAN mismatch detection
- Weak key and signature algorithm detection
- Deprecated TLS version detection (SSLv2/3, TLS 1.0/1.1)
- Incomplete certificate chain detection
- Wildcard certificate detection

## Requirements

```
pyOpenSSL
cryptography
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### As a library

```python
from certcheck import check_cert

result = check_cert("example.com")        # defaults to port 443
result = check_cert("example.com:8443")   # custom port

print(result["days_left"])   # days until expiry
print(result["ok"])          # False if any critical issue exists
print(result["issues"])      # list of {"level": "critical"|"warn"|"info", "msg": str}
```

### From the command line

```bash
python certcheck.py example.com
```

Exits with:
- `0` — no issues
- `1` — warnings only
- `2` — critical issues

### Example output

```bash
=== TLS CERTIFICATE REPORT FOR: example.com:443 ===
Property           | Value
------------------------------------------------------------
Status             | PASS (OK)
Common Name (CN)   | example.com
Days Remaining     | 87 days
Valid From         | 2026-05-31T21:39:12+00:00
Valid Until        | 2026-08-29T21:41:26+00:00
TLS Version        | TLSv1.3
Cipher Suite       | TLS_AES_256_GCM_SHA384
Chain Length       | 4 cert(s)
Self-Signed?       | False

=== DISCOVERED ISSUES (1) ===
Severity   | Description
------------------------------------------------------------
ℹ️ INFO    | Wildcard certificate

```

## Issue Levels

| Level | Meaning |
|---|---|
| `critical` | `result["ok"]` is set to `False` |
| `warn` | Notable problem, but not blocking |
| `info` | Informational only |

## Testing

### Quick manual test

Run against a known-good site:

```bash
python certcheck.py google.com
```

Run against an expired cert (test site maintained by BadSSL):

```bash
python certcheck.py expired.badssl.com
```

Run against a self-signed cert:

```bash
python certcheck.py self-signed.badssl.com
```

Run against a hostname mismatch:

```bash
python certcheck.py wrong.host.badssl.com
```

### Check the exit code

```bash
python certcheck.py google.com
echo $?   # 0 = ok, 1 = warnings, 2 = critical
```

### Use in a script

```python
from certcheck import check_cert

hosts = ["google.com", "github.com", "example.com"]

for host in hosts:
    result = check_cert(host)
    status = "OK" if result["ok"] else "FAIL"
    print(f"{host}: {status} — {result['days_left']} days left")
    for issue in result["issues"]:
        print(f"  [{issue['level'].upper()}] {issue['msg']}")
```
