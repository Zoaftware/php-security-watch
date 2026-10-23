# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-23

First public release.

### Added

- Eleven nightly checks: `os`, `patches`, `reboot`, `php`, `services`, `runtimes`, `libraries`,
  `wordpress`, `news`, `intrusion` and `sites`.
- Every PHP on the server is found (system packages, Ondřej Surý, Remi, cPanel EasyApache, Plesk,
  DirectAdmin, CloudLinux alt-php, `/usr/local`, Docker containers) and compared with php.net.
- Library advisories for Composer (Packagist) and npm, yarn, pnpm, Python and Ruby lock files (OSV).
- CISA "actively exploited" list matched against the software found on the server.
- Web shell signatures, PHP in upload folders, odd processes, web user crontabs and SSH keys.
- Site checks: every host still answers, TLS expiry, exposed `.env`, `.git`, `phpinfo()`, `phpunit`.
- Report mode (default) and fix mode: security updates plus tested, opt-in service restarts.
- Alerts by email (sendmail or SMTP) and webhook (Slack, Discord, Telegram, ntfy, JSON), only when
  something changes, plus a weekly digest and reminders for open findings.
- `install.sh` (systemd timer, cron.d or Alpine crontab) and `uninstall.sh` (`--purge`).

[1.0.0]: https://github.com/Zoaftware/php-security-watch/releases/tag/v1.0.0
