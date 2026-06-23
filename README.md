# f5_ssl_cipher_report

Python script that enumerates BIG-IP LTM virtual servers and their associated
Client/Server SSL profiles, reporting each profile's cipher string (and,
optionally, the fully expanded cipher list) via the iControl REST API.

> **Run this remotely, not on the BIG-IP.** The script is a client of the
> iControl REST API — run it from your workstation or a jump host that has
> network access to the BIG-IP management interface. It is **not** a TMOS
> on-box script and is not intended to be executed from the BIG-IP shell.

## Requirements

- Python 3.10+ with the `requests` library (`pip install -r requirements.txt`),
  on a host **separate from the BIG-IP**
- Network access to the BIG-IP management interface (REST)
- A BIG-IP account with REST access. The `--fullciphers` option additionally
  runs `tmm --clientciphers` / `tmm --serverciphers` through the
  `/mgmt/tm/util/bash` endpoint, which requires an account with **bash /
  Administrator (or Resource Administrator) privileges**.

## Usage

```
python3 f5_ssl_scan.py [--host <host>] [--username <username>] \
    [--csv <output_filename.csv>] [--fullciphers] [--verbose]
```

The password is **never** accepted on the command line. It is read from the
`F5_PASSWORD` environment variable, or — if that is unset — entered at a secure
no-echo prompt. The username may be passed with `--username` or via `F5_USERNAME`.
This keeps credentials out of your shell history and the process list.

```
export F5_HOST=10.1.1.245
export F5_USERNAME=admin
export F5_PASSWORD='...'
python3 f5_ssl_scan.py --fullciphers
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--host` | yes\* | BIG-IP REST interface, typically the management IP (\*or set `F5_HOST`) |
| `--username` | yes\* | Username for REST authentication (\*or set `F5_USERNAME`) |
| `--csv` | no | Write a per-virtual summary report to this CSV file |
| `--fullciphers` | no | Expand and print the complete negotiated cipher list for each SSL profile (requires bash privileges; see above) |
| `--ca-bundle` | no | Path to a CA bundle used to verify the BIG-IP management certificate |
| `--insecure` | no | Disable TLS certificate verification of the management interface (not recommended) |
| `--timeout` | no | Per-request timeout in seconds (default: 30) |
| `--verbose` | no | Print additional detail during execution (each profile/virtual found, non-SSL profiles) |

The password is supplied only via the `F5_PASSWORD` environment variable or the
secure prompt — there is no `--password` flag.

### TLS verification

By default the script **verifies** the BIG-IP management certificate against the
system CA store. Most BIG-IPs use a self-signed management cert, so you will
typically either point `--ca-bundle` at the device's CA/cert, or pass
`--insecure` to skip verification (which restores the original behavior and
suppresses the urllib3 insecure-request warning).

On an authentication failure (HTTP 401) or other HTTP error, the script aborts
with a clear message rather than a stack trace, and exits with status `2`.

## Console output

```
Found Client SSL profile: clientssl
 -> Ciphers: DEFAULT
 -> Retrieving complete cipher list
...
*********************
Virtual server: /Common/accounts_receivable_https_vs (/Common/10.1.10.70:443)
 -> Profile found: clientssl (Context: clientside)
   -> Cipher string: DEFAULT
   -> Parent profile: none
   -> Complete cipher list: 
       ID  SUITE                            BITS PROT    CIPHER              MAC     KEYX
 0: 49199  ECDHE-RSA-AES128-GCM-SHA256      128  TLS1.2  AES-GCM             SHA256  ECDHE_RSA 
 1: 49199  ECDHE-RSA-AES128-GCM-SHA256      128  DTLS1.2  AES-GCM             SHA256  ECDHE_RSA 
 ...
94:  4865  TLS13-AES128-GCM-SHA256          128  TLS1.3  AES-GCM             NULL    *         
95:  4866  TLS13-AES256-GCM-SHA384          256  TLS1.3  AES-GCM             NULL    *         
   -> Non-SSL Profile

Report complete.
```

The `Complete cipher list` block is printed only when `--fullciphers` is
supplied and only for SSL profiles bound to a virtual server.

## CSV output

When `--csv` is supplied, a summary row is written for every virtual server
(independent of `--fullciphers`, which only affects console output):

```
Virtual Server Path,Virtual Server Destination,CLIENT SSL PROFILE,PARENT CLIENT SSL PROFILE,SERVER SSL PROFILE,PARENT SERVER SSL PROFILE
/Common/accounts_receivable_https_vs,/Common/10.1.10.70:443,clientssl,none,none,none
/Common/accounts_receivable_vs,/Common/10.1.10.70:80,none,none,none,none
/Common/web_app_42,/Common/10.1.10.66:443,clientssl,none,none,none
```

## Testing

Unit-free linting/type-checking runs in CI (ruff, flake8, mypy on Python
3.10–3.13). Because the script's real behavior depends on a live BIG-IP, there
is also a **manual** smoke suite at [`scripts/smoke.sh`](scripts/smoke.sh) that
exercises every flag, credential path, error abort, and output mode against a
real device. It is not run in CI (it needs hardware). To run it:

```
export F5_HOST=<mgmt-ip> F5_USERNAME=admin F5_PASSWORD='<password>'
bash scripts/smoke.sh
```

It assumes a reachable lab BIG-IP with a self-signed management certificate,
checks each invocation's exit code and output, and prints a pass/fail summary.
