# Security policy

## Supported versions

Security fixes are made for the latest release of uFTP. Older releases do not get fixes: upgrade to the latest
one (see the release notes for what changes between versions).

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately with GitHub: open the **Security** tab of the repository and choose **Report a
vulnerability** (<https://github.com/kingk85/uFTP/security/advisories/new>).

Please include:
- the version of uFTP (the first line of the log says it) and how it was built (with or without OpenSSL, IPv6);
- what you did and what happened, ideally with the commands sent to the server;
- the configuration that matters (without passwords), and the operating system;
- if you can, a small script that reproduces it.

## What to expect

- A first answer within **7 days**.
- The problem is checked, fixed and a new release is made. We tell you when the fix is ready.
- When the fix is released, the problem is published as a security advisory (with a CVE where it applies), and the
  person who reported it is credited if they want to be.
- Please keep the details private until the fix is released. We ask for at most **90 days**.

## Notes for the people who run uFTP

- Build with OpenSSL and use `FORCE_TLS = true` if the server is reachable from the Internet.
- Start the server from a directory that other users cannot write to: `./uftpd.cfg` has the precedence over
  `/etc/uftpd.cfg`.
- Do not use the sample `uftpd.cfg` as it is: it has example users and a home directory of `/`.
- Passwords can be written as hashes (`./uFTP --hash-password`).
- The limits for connections, logins and free space (`MAX_CONNECTION_NUMBER_PER_IP`, `MAX_CONNECTION_RATE_PER_IP`,
  `MAX_CONNECTION_PER_ACCOUNT`, `MIN_FREE_SPACE_MB`) are described in the comments of `uftpd.cfg`.
