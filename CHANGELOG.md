# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-10-23

### Security

- Never execute a discovered binary that a non-root user could have replaced. To read versions,
  1.0.0 ran every `php`, `php-fpm`, `node` and `python3` it found (including `/opt/*`,
  `/usr/local/php*` and `~/.nvm` in every home folder), plus `nginx -T`, `apachectl -S`, `sendmail`
  and the config tests before a restart, as root. A user who owned one of those files or folders
  (or a hacked site running as that user) could swap it for a script and get root at the next run.
  Now a program runs only when the real file (after every symlink) and every folder above it belong
  to root and nobody else can write to them. Otherwise it is not run and the report shows a warning
  ("Did not run …") with the fix. Node.js from nvm or n is still checked: the version is read from
  its folder name, without running it. Upgrade: download 1.0.1 and run `sudo ./install.sh` again.

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

[1.0.1]: https://github.com/Zoaftware/php-security-watch/releases/tag/v1.0.1
[1.0.0]: https://github.com/Zoaftware/php-security-watch/releases/tag/v1.0.0
