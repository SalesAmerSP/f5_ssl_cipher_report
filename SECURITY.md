# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report them privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security tab → "Report a vulnerability"). We aim to
acknowledge reports within a few business days.

## Scope and usage notes

This is an administrative read-only reporting tool for F5 BIG-IP. A few
operational security notes for users:

- **Credentials** are read from the `F5_HOST` / `F5_USERNAME` / `F5_PASSWORD`
  environment variables or an interactive prompt. There is no `--password`
  flag, so passwords are kept out of shell history and the process list.
- **TLS verification is on by default.** Use `--ca-bundle` to pin the BIG-IP
  management certificate; `--insecure` disables verification and should only be
  used in trusted lab environments.
- The `--fullciphers` option runs `tmm` via the BIG-IP `/util/bash` endpoint,
  which requires a privileged account. Use a least-privilege account where
  possible.
