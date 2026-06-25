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
| `--utilization` | no | With `--csv`, also write `<csv>_utilization.csv`: per-profile handshake counts by protocol/cipher attribute (from SSL profile stats), flagging legacy protocols/ciphers still in use |
| `--ca-bundle` | no | Path to a CA bundle used to verify the BIG-IP management certificate |
| `--insecure` | no | Disable TLS certificate verification of the management interface (not recommended) |
| `--min-tls` | no | Minimum TLS version (`1.0`/`1.1`/`1.2`/`1.3`) for connecting to the management interface; lower it for legacy TMOS such as 13.x (see Troubleshooting). Values below 1.2 are insecure. |
| `--timeout` | no | Per-request timeout in seconds (default: 30) |
| `--verbose` | no | Print additional detail during execution (each profile/virtual found, non-SSL profiles) |
| `--debug` | no | Emit detailed diagnostic logging to **stderr** (each REST request, HTTP status, byte count, and timing, plus `urllib3` connection logs). Credentials are never logged. Combine with `2>debug.log` to capture. |

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

### Troubleshooting: TLS handshake fails / `UNEXPECTED_EOF_WHILE_READING`

If the script aborts with an SSL error such as
`SSLError(... UNEXPECTED_EOF_WHILE_READING ...)` or `UNSUPPORTED_PROTOCOL`, the
TLS handshake to the device failed before any HTTP happened — so `--insecure`
(which only skips certificate *verification*) will **not** help. The two common
causes are:

1. **Wrong target — a data-plane VIP, not the management interface.** iControl
   REST lives on the BIG-IP **management** address (or a self-IP whose
   port-lockdown allows TMUI/443). Point `--host` at the management IP and check
   the certificate: `openssl s_client -connect <host>:443` — a real mgmt
   interface presents the device's self-signed cert (often
   `CN = localhost.localdomain`), whereas a VIP presents an application cert.

2. **A legacy device that predates TLS 1.2.** Older TMOS management httpd (e.g.
   **13.1**) defaults to TLS 1.0, which a modern OpenSSL client refuses by
   default (its ClientHello floors at TLS 1.2), and the device closes the
   socket. Retry with `--min-tls 1.0`:

   ```
   python3 f5_ssl_scan.py --host <mgmt-ip> --insecure --min-tls 1.0
   ```

   `--min-tls` below 1.2 also drops the OpenSSL security level so the legacy
   ciphers those devices present are accepted. It is a security downgrade —
   use it only to reach old management interfaces, and prefer upgrading the
   device's `sys httpd ssl-protocol` instead.

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

When `--csv` is supplied, a summary row is written for every virtual server:

```
Virtual Server Path,Virtual Server Destination,CLIENT SSL PROFILE,PARENT CLIENT SSL PROFILE,SERVER SSL PROFILE,PARENT SERVER SSL PROFILE
/Common/accounts_receivable_https_vs,/Common/10.1.10.70:443,clientssl,none,none,none
/Common/accounts_receivable_vs,/Common/10.1.10.70:80,none,none,none,none
/Common/web_app_42,/Common/10.1.10.66:443,clientssl,none,none,none
```

### Per-profile cipher CSV (`--csv` + `--fullciphers`)

When `--fullciphers` is supplied alongside `--csv`, a companion
`<csv>_ciphers.csv` (e.g. `report.csv` -> `report_ciphers.csv`) is also written.
It has one row per **SSL profile** (not per virtual server, so a profile shared
by many virtuals is listed once), with its expanded cipher list as
`SUITE (PROT)` lines:

```
SSL PROFILE,CONTEXT,PARENT PROFILE,CIPHER STRING,CIPHER LIST
clientssl,Client,none,DEFAULT,ECDHE-RSA-AES128-GCM-SHA256 (TLS1.2); TLS13-AES128-GCM-SHA256 (TLS1.3); ...
clientssl-quic,Client,/Common/clientssl,cipher group /Common/f5-quic,TLS13-AES128-GCM-SHA256 (TLS1.3); TLS13-AES256-GCM-SHA384 (TLS1.3)
```

Each profile's full list stays on one line (entries joined with `; `) so a
profile never spreads across multiple spreadsheet rows. The `tmm`
index/ID/BITS/MAC/KEYX columns are intentionally dropped: they are noise for
this purpose and their column positions shift between TMOS releases, which would
make a diff lie. `PROT` is kept because protocol coverage is exactly what tends
to change on an upgrade. This file is designed for diffing the same profile
across two TMOS versions to see which ciphers/protocols changed. If the `tmm`
output ever fails to parse, the raw text is preserved so nothing is lost.

A profile that uses a **cipher group** rather than a cipher string reports its
`CIPHER STRING` as `cipher group <path>` (TMOS stores `ciphers` as `none` in
that case), and the cipher list is expanded from the group's rules.

### Cipher utilization CSV (`--csv` + `--utilization`)

The cipher CSV above tells you which ciphers a profile *offers*; `--utilization`
tells you which are *actually being used*, so before removing a protocol or
cipher ahead of a TMOS upgrade you can confirm whether real clients still
negotiate it. With `--csv`, a companion `<csv>_utilization.csv` (e.g.
`report.csv` -> `report_utilization.csv`) is written with one row per SSL
profile and handshake counts read from the profile's `/stats`:

```
SSL PROFILE,CONTEXT,TOTAL HANDSHAKES,SSLv3,TLS1.0,TLS1.1,TLS1.2,TLS1.3,RC4,DES/3DES,MD5,SHA1-MAC,CBC-AES/CAM,NULL,ADH-anon,RSA-keyx-noPFS,RSA-1024,DEPRECATED-IN-USE
clientssl,Client,35319,0,0,0,35319,0,0,0,0,39,39,0,0,0,0,no
```

TMOS counts handshakes by cryptographic **attribute** (protocol, bulk cipher,
key exchange, MAC, key size), not by exact suite name, so these columns answer
"is this legacy protocol/cipher still being negotiated?" rather than "which exact
suite". `DEPRECATED-IN-USE=YES` flags any profile still negotiating a legacy
protocol (SSLv3/TLS1.0/TLS1.1) or broken cipher (RC4, DES/3DES, MD5, NULL,
anon-DH, RSA-1024); `CBC-AES/CAM` and `SHA1-MAC` are shown but not auto-flagged
since they are not yet removed by default. Counts are **cumulative since the last
stat reset / reboot**, not a time window — for a representative sample, reset the
profile stats (`tmsh reset-stats ltm profile client-ssl`) and re-run after a
period of live traffic. Exact per-suite counts are not available from stats; that
would require an iRule logging `[SSL::cipher name]` or AVR.

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
