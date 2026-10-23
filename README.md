# php-security-watch

**A nightly security guard for any Linux server that runs PHP.** One file, no dependencies beyond
Python 3, installs in a minute and tells you in plain words what needs your attention — before
someone else finds it.

[![CI](https://github.com/Zoaftware/php-security-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Zoaftware/php-security-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Español](README.es.md)

Every night it looks at the whole server, not only PHP: the operating system, waiting security
updates, every PHP binary and its settings, the libraries your sites ship (`composer.lock`,
`package-lock.json`, …), WordPress, exposed services, signs of a break-in, and whether every site
still answers. It compares all of it against the official sources (php.net, Packagist, OSV, CISA's
list of actively exploited flaws, the Ubuntu security tracker, endoflife.date) and sends you one
short email or chat message — only when something is new, got fixed, or once a week as a summary.

By default it **only reads and reports**. If you want, it can also install the security updates and
restart the affected services for you, testing each config first and checking the site still
answers afterwards.

---

## Contents

- [What it checks](#what-it-checks)
- [Install](#install)
- [First run](#first-run)
- [What a report looks like](#what-a-report-looks-like)
- [Alerts: email, Slack, Discord, Telegram, ntfy, webhook](#alerts)
- [Fix mode](#fix-mode)
- [Configuration](#configuration)
- [Commands and exit codes](#commands-and-exit-codes)
- [Files it creates](#files-it-creates)
- [Upgrade](#upgrade)
- [Uninstall](#uninstall)
- [Supported systems](#supported-systems)
- [Privacy: what leaves your server](#privacy-what-leaves-your-server)
- [FAQ](#faq)
- [Contributing](#contributing) · [Security](#security) · [License](#license)

---

## What it checks

| Check | What it looks at | Source of truth |
|---|---|---|
| `os` | The operating system release still gets security updates | endoflife.date |
| `patches` | Security updates waiting in apt, dnf, yum, apk or zypper; whether automatic updates are on | your package manager |
| `reboot` | A reboot is pending (new kernel) and which services still run replaced libraries | `/proc`, needs-restarting |
| `php` | **Every** PHP on the server (system, `/opt/remi`, `/opt/cpanel/ea-php*`, Plesk, DirectAdmin, `/usr/local`, Docker containers): version vs the latest security release of its branch, end of life, risky `php.ini` settings | php.net, endoflife.date |
| `services` | PHP-FPM, MySQL/MariaDB, PostgreSQL, Redis, Memcached, Elasticsearch, MongoDB listening on a public interface; ports Docker publishes | `ss` / `/proc/net` |
| `runtimes` | Node.js and Python versions vs their security releases and end of life | nodejs.org, endoflife.date |
| `libraries` | `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`, virtualenvs, `Gemfile.lock` | Packagist security advisories, OSV.dev |
| `wordpress` | Core version, core files changed or added (checksums), plugins closed on wordpress.org | wordpress.org APIs |
| `news` | Flaws CISA added to its **actively exploited** list that match software on this server; new PHP security releases; Ubuntu packages with open high/critical CVEs | CISA KEV, php.net, Ubuntu tracker |
| `intrusion` | Web shell signatures in PHP files, PHP inside upload folders, programs in `/tmp`, odd or crypto-mining processes, web users' crontabs and SSH keys, PHP-FPM crashes | the server itself |
| `sites` | Every site found in nginx / Apache / Caddy still answers, TLS certificate expiry, exposed `.env`, `.git`, `phpinfo()`, `phpunit` `eval-stdin.php` | HTTPS requests to your own sites |

Every finding has a level — **critical**, **warning**, **fixed** or **info** — and a one-line
"what to do". A check that cannot reach its source says so instead of reporting a false "all good".

## Install

You need a Linux server, root, and Python 3.6 or newer (already present on every current
Ubuntu, Debian, RHEL/Rocky/Alma, Fedora, Alpine and openSUSE; `--deps` installs it if missing).

```sh
curl -fsSL https://github.com/Zoaftware/php-security-watch/archive/refs/tags/v1.0.0.tar.gz | tar xz
cd php-security-watch-1.0.0
sudo ./install.sh --email you@example.com
```

Or with git:

```sh
git clone https://github.com/Zoaftware/php-security-watch.git
cd php-security-watch
sudo ./install.sh --email you@example.com
```

That's it. It runs every night at 03:00 (server time) and emails you when something needs attention.

### Install options

| Option | What it does | Default |
|---|---|---|
| `--email you@example.com` | Where to send alerts (comma separated for several) | none |
| `--webhook URL` | Slack, Discord, Telegram, ntfy or any JSON webhook | none |
| `--smtp-url smtps://host:465` | Send through an SMTP server instead of the local `sendmail` | local sendmail |
| `--mode report\|fix` | `report` only looks; `fix` also installs security updates ([Fix mode](#fix-mode)) | `report` |
| `--time 03:00` | When to run every day | `03:00` |
| `--timezone America/Costa_Rica` | Time zone for `--time` | server time |
| `--no-timer` | Install without scheduling it (you run it yourself or from your own scheduler) | |
| `--run-now` | Run the first check right after installing | |
| `--deps` | Install `python3`, `ca-certificates` and `ss` with your package manager first | |

Examples:

```sh
# Slack alerts, run at 02:30 Costa Rica time, and look right away
sudo ./install.sh --webhook https://hooks.slack.com/services/T000/B000/XXXX --time 02:30 --timezone America/Costa_Rica --run-now

# Email through Gmail / Google Workspace / any provider (put the password in the config file afterwards)
sudo ./install.sh --email you@example.com --smtp-url smtps://smtp.gmail.com:465

# Fully automatic: install security updates and reload PHP-FPM + the web server
sudo ./install.sh --email you@example.com --mode fix
```

The installer:

1. copies the program to `/usr/local/sbin/php-security-watch`, pointing it to the Python it found;
2. writes `/etc/php-security-watch.conf` (root only, `0600`) — **only the first time**; if it already
   exists it is kept and the new example is saved next to it as `php-security-watch.conf.new`;
3. creates `/var/lib/php-security-watch` for the reports;
4. schedules it with a **systemd timer** (`php-security-watch.timer`), or `/etc/cron.d` on systems
   without systemd, or `/etc/crontabs/root` on Alpine.

Running `install.sh` again is safe: it upgrades the program and keeps your settings.

## First run

```sh
sudo php-security-watch test-notify       # check the email / webhook reaches you
sudo php-security-watch run --no-notify   # first full look (reads every PHP file)
sudo php-security-watch status            # last result, and when the next run is
```

The first run and the weekly digest run read every PHP file for web shell signatures. The other
nights only read files changed in the last `INTRUSION_DAYS` days. `run --deep` forces the full read.

How long it takes depends on how many files the server holds. Measured on a 4 GB server with 35 sites
and their release copies: the first run took 584 s, and a nightly run that read 628,901 changed PHP files
took 580 s, both at low priority while the sites kept serving.

## What a report looks like

An example from a made-up server (the email and chat messages carry the same text):

```text
php-security-watch 1.0.0 - web1 - 2026-10-23 09:00 UTC
Ubuntu 24.04.3 LTS - mode report, changed-files intrusion scan

Result: 4 need attention (2 critical, 2 warning, 0 fixed, 3 info, 8 ok)

NEEDS ATTENTION
[critical] php       PHP 8.3.11 (php8.3-fpm 8.3.11-1+ubuntu24.04.1+deb.sury.org+1 from packages.sury.org) is missing 2 security releases: 8.3.12, 8.3.14.  (new)
      Found at /usr/sbin/php-fpm8.3. Latest 8.3 release: 8.3.14.
      Fix: Update PHP to 8.3.14 or later and reload PHP-FPM.
[critical] libraries /var/www/shop: 1 library with known security flaws (PHP): guzzlehttp/guzzle 7.4.0.  (new)
      guzzlehttp/guzzle 7.4.0: CVE-2022-29248 (high) Cross-domain cookie leakage in Guzzle - fixed in 7.4.3
      guzzlehttp/guzzle 7.4.0: CVE-2022-31042 (high) Failure to strip the Cookie header on change in host or HTTP downgrade - fixed in 7.4.4
      Fix: In /var/www/shop run `composer update <package> --with-dependencies`, test the site, deploy. This tool never changes application code.
[warning]  libraries /var/www/blog: 1 library with known security flaws (JavaScript): lodash 4.17.15 (dev).
      lodash 4.17.15: CVE-2021-23337 (high) Command Injection in lodash - fixed in 4.17.21
      (dev) = only used to build the site, never run for visitors, so it counts as a warning at most.
      Fix: In /var/www/blog run `npm audit fix (or npm update <package>)`, test the site, deploy. This tool never changes application code.
[warning]  sites     The TLS certificate of shop.example.com expires in 9 days.
      Fix: Renew it (certbot renew) and check the renewal timer.

CHECKED
[ok] os        Ubuntu 24.04.3 LTS gets security updates until 2029-05-31.
[ok] patches   No security updates waiting (apt).
[ok] patches   Automatic security updates are on (unattended-upgrades).
[ok] reboot    No reboot pending.
[ok] services  PHP-FPM, databases and caches only listen on local or private addresses.
[ok] libraries 3 projects with no known flaws: /var/www/api, /var/www/admin, /var/www/landing.
[info] news      php.net security releases in the last 14 days: PHP 8.3.14 (2026-10-16).
[ok] intrusion No signs of intrusion (read 1,842 PHP files changed in the last 7 days, upload folders, temp folders, processes, crontabs, SSH keys, crashes).
[ok] sites     6 of 6 sites answer.

Sources: CISA KEV ok, OSV ok, Packagist ok, Ubuntu tracker ok, endoflife.date ok, php.net ok
Took 74 s. https://github.com/Zoaftware/php-security-watch
```

Every line under a finding is the evidence; the `Fix:` line is the one thing to do. `(new)` marks what
was not in the last alert.

The same report is saved as JSON (`last.json`) for dashboards and scripts.

## Alerts

Set `NOTIFY_EMAIL`, `WEBHOOK_URL`, or both, in `/etc/php-security-watch.conf`. Then
`sudo php-security-watch test-notify`.

**When does it alert?** (`NOTIFY_WHEN`)

- `new` (default): something new needs attention, something got fixed, a warning became critical,
  or it is the weekly digest day (`DIGEST_WEEKDAY`, Monday by default). An alert that is still open is
  repeated every `REMIND_DAYS` days (7). No news, no message.
- `attention`: every night that something needs attention or got fixed.
- `always`: every night.

### Email

```ini
NOTIFY_EMAIL=you@example.com, team@example.com
# Without SMTP_URL it uses the local sendmail (postfix, exim, msmtp, ...)
SMTP_URL=smtps://smtp.example.com:465        # TLS; or smtp://smtp.example.com:587 for STARTTLS
SMTP_USER=alerts@example.com
SMTP_PASSWORD_FILE=/root/.smtp-password      # a root-only file holding only the password
MAIL_FROM=alerts@example.com
```

The subject line tells you the state at a glance, for example
`[php-security-watch] web1: 3 need attention, 1 fixed`.

### Chat and push

| Service | `WEBHOOK_URL` |
|---|---|
| Slack | `https://hooks.slack.com/services/...` (incoming webhook) |
| Discord | `https://discord.com/api/webhooks/...` |
| Telegram | `https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>` |
| ntfy (phone push) | `https://ntfy.sh/<your-secret-topic>` or your own ntfy server |
| Anything else | any URL that accepts a JSON `POST` — it receives the full JSON report |

The format is detected from the URL; set `WEBHOOK_FORMAT=slack|discord|telegram|ntfy|json` to force one.

## Fix mode

`MODE=report` (default) never changes anything on the server. It does refresh the package lists
(`apt-get update`, like any update check) unless you set `APT_UPDATE=no`.

`MODE=fix` (or `run --apply` for a single run) also:

1. **installs the pending security updates** — only the security ones (apt from the `-security`
   pockets, `dnf/yum --security`, `zypper patch --category security`, `apk upgrade` on Alpine);
2. **restarts the services that still run old code**, as allowed by `RESTART_SERVICES`:

| `RESTART_SERVICES` | What may be restarted |
|---|---|
| `none` (default) | nothing — the report lists what still needs a restart |
| `php-fpm` | PHP-FPM pools (graceful reload) |
| `web` | PHP-FPM + nginx / Apache / Caddy / LiteSpeed |
| `all-safe` | every service except the ones that are never safe to bounce: databases, Docker/containerd, networking and firewalls, dbus, systemd, cron, cloud agents |

Before each restart it tests the config (`php-fpm -t`, `nginx -t`, `apachectl configtest`,
`sshd -t`) and skips the restart if the test fails. After it, it checks the service is running again
and that every site answers as it did before the update; anything that changed is a **critical**
finding in that night's alert. **It never reboots the server** — a pending reboot is reported for
you to schedule.

## Configuration

All settings live in `/etc/php-security-watch.conf` (`KEY=VALUE`, `#` for comments). Any setting can
also be given for one run as an environment variable: `PSW_<KEY>=value`, e.g.
`PSW_SCAN_PATHS=/var/www php-security-watch run`.

| Key | Default | Meaning |
|---|---|---|
| `MODE` | `report` | `report` or `fix` |
| `RESTART_SERVICES` | `none` | `none`, `php-fpm`, `web`, `all-safe` (fix mode only) |
| `APT_UPDATE` | `yes` | refresh package lists before looking for updates |
| `SCAN_PATHS` | `/var/www /srv /home /opt` | where your sites and lock files live |
| `SCAN_MAX_DEPTH` | `6` | how deep to look for lock files |
| `SKIP_PATHS` | | folders to leave out (backups, big media folders) |
| `WEB_USERS` | `auto` | users that run your sites; `auto` = users of the PHP-FPM / web processes |
| `CHECK_URLS` | `auto` | `auto` = every host name in nginx / Apache / Caddy, `none`, or a list |
| `INTRUSION_DAYS` | `7` | PHP files changed in this many days are read every night |
| `KEV_DAYS` | `30` | look at CISA's actively exploited list of the last N days |
| `KEV_EXTRA_KEYWORDS` | | extra product names to match, e.g. `Moodle Roundcube` |
| `NOTIFY_EMAIL` | | alert addresses, comma separated |
| `SMTP_URL` · `SMTP_USER` · `SMTP_PASSWORD_FILE` · `SMTP_PASSWORD` · `MAIL_FROM` | | SMTP sending (see [Email](#email)) |
| `WEBHOOK_URL` · `WEBHOOK_FORMAT` | · `auto` | chat / push alerts (see [Chat and push](#chat-and-push)) |
| `NOTIFY_WHEN` | `new` | `new`, `attention` or `always` |
| `DIGEST_WEEKDAY` | `1` | weekly summary day, 1 = Monday … 7 = Sunday, 0 = never |
| `REMIND_DAYS` | `7` | repeat an open alert after this many days |
| `DOCKER` | `auto` | also look inside running containers and at published ports (`auto`, `yes`, `no`) |
| `TIMEOUT` | `40` | seconds to wait for each online source |
| `STATE_DIR` | `/var/lib/php-security-watch` | reports, history and alert memory |
| `IGNORE` | | findings you reviewed and accept: CVE / GHSA / PKSA ids or finding keys |

The commented example with every key is [`php-security-watch.conf.example`](php-security-watch.conf.example).
A setting with a typo is reported as a warning instead of being silently ignored.

### Accepting a finding

If you reviewed something and decided to live with it (a library flaw in code you never call, a
port you protect with a firewall elsewhere), add its id to `IGNORE`:

```ini
IGNORE=CVE-2026-12345 GHSA-xxxx-xxxx-xxxx services:listen-0.0.0.0-6379
```

The finding stays in the report as `info` and never alerts again. The ids and keys are in `last.json`.

## Commands and exit codes

```
php-security-watch run [--apply] [--no-notify] [--json] [--quiet] [--deep] [--only php,libraries]
php-security-watch status
php-security-watch test-notify
php-security-watch checks
php-security-watch --config /path/to/other.conf run
```

| Exit code | Meaning |
|---|---|
| `0` | nothing needs attention |
| `1` | something needs attention (at least one critical or warning) |
| `2` | the tool itself had a problem: another run in progress, an alert could not be sent, a bad setting |

So it also works in CI or your own monitoring: `php-security-watch run --quiet --no-notify --only libraries || page-me`.

## Files it creates

| Path | What |
|---|---|
| `/usr/local/sbin/php-security-watch` | the program |
| `/etc/php-security-watch.conf` | your settings (root only) |
| `/var/lib/php-security-watch/last.txt`, `last.json` | the latest report |
| `/var/lib/php-security-watch/reports/` | the last 60 reports (text + JSON) |
| `/var/lib/php-security-watch/seen.json` | what was already alerted, so you are not told twice |
| `/var/lib/php-security-watch/runs.log` | one line per run |
| `/etc/systemd/system/php-security-watch.{service,timer}` | the schedule (or `/etc/cron.d/php-security-watch`, or a line in `/etc/crontabs/root`) |

Nothing else on the server is touched in report mode.

## Upgrade

Download the new release and run its installer; your config is kept.

```sh
curl -fsSL https://github.com/Zoaftware/php-security-watch/archive/refs/tags/v1.0.0.tar.gz | tar xz
cd php-security-watch-1.0.0 && sudo ./install.sh
```

New settings, if any, appear in `/etc/php-security-watch.conf.new` to compare with yours.

## Uninstall

From the folder you installed from (or a fresh download of it):

```sh
sudo ./uninstall.sh            # remove the program and its schedule, keep your config and reports
sudo ./uninstall.sh --purge    # also delete /etc/php-security-watch.conf and /var/lib/php-security-watch
```

It removes only what `install.sh` created: the program, the systemd timer and service (or the cron
entry), and with `--purge` the config and reports. Security updates it installed in fix mode stay
installed — those are the fixes.

Lost the folder? This does the same by hand:

```sh
sudo systemctl disable --now php-security-watch.timer
sudo rm -f /etc/systemd/system/php-security-watch.timer /etc/systemd/system/php-security-watch.service
sudo systemctl daemon-reload
sudo rm -f /etc/cron.d/php-security-watch /usr/local/sbin/php-security-watch
sudo sed -i '/# php-security-watch/d' /etc/crontabs/root 2>/dev/null   # Alpine only
sudo rm -rf /etc/php-security-watch.conf /var/lib/php-security-watch   # only if you want the data gone too
```

## Supported systems

Tested on every push (see [CI](.github/workflows/ci.yml)) by installing, running and uninstalling it on:

- Ubuntu 24.04 and 22.04
- Debian 12
- Rocky Linux 9 and 8 (also RHEL, AlmaLinux, CentOS Stream, Oracle Linux)
- Alpine 3.20
- the official `php:8.3-fpm` Docker image

It also runs on Fedora, openSUSE / SLES and Amazon Linux. Panels such as cPanel/WHM, Plesk,
DirectAdmin, CloudPanel, RunCloud, Ploi, Forge and ServerPilot are just Linux underneath: it finds
their extra PHP versions on its own.

## Privacy: what leaves your server

To compare versions it calls these public APIs over HTTPS:

| Source | What is sent |
|---|---|
| packagist.org | the names and versions of your Composer packages |
| api.osv.dev | the names and versions of your npm, Python and Ruby packages |
| php.net, nodejs.org, endoflife.date | the PHP branch / product name |
| api.wordpress.org | the WordPress version and the slugs of installed plugins |
| CISA KEV (GitHub mirror), ubuntu.com | nothing — the public lists are downloaded |
| your own sites | normal HTTPS requests, sent to this server first |

No telemetry, no account, no third-party service of ours. Alerts go only to the addresses and URLs
you configure. The reports stay in `/var/lib/php-security-watch`, readable by root only.

## FAQ

**Will it slow my server down?** It runs at low CPU and disk priority (`Nice=10`, idle I/O class)
at night, and reads only recently changed files. On a 4 GB server with 35 sites a run took about
10 minutes; a server with fewer files is faster.

**Does it replace a firewall, a WAF or malware cleanup?** No. It is the night watchman that tells you
what is open, old or strange, with the exact fix. Cleaning a hacked site still needs a person.

**Is a "Possible web shell" finding always a hack?** Not always — some plugins really do run encoded
code. Open the file: if it is part of a plugin you installed, compare it with the original download
and add its key to `IGNORE`. If you don't recognise it, treat the site as compromised.

**My distribution backports fixes; will it cry wolf about the PHP version?** For PHP from your
distribution's packages it trusts your package manager's security updates instead of comparing with
php.net version numbers, because Debian, Ubuntu and RHEL backport fixes into older version numbers.
Version checks against php.net apply only to PHP that follows php.net releases: built by hand,
official Docker images, the Ondřej Surý and Remi repositories, cPanel EasyApache and Plesk.

**Can I run it without root?** Yes, with less coverage (no package, process, crontab or other users'
files). It says so at the top of the report.

**How do I scan only one project?** `PSW_SCAN_PATHS=/var/www/shop php-security-watch run --only libraries,intrusion --no-notify`

**Does it work offline?** The local checks (intrusion, services, reboot, sites) do. The checks that
need a source say "Could not read …" instead of pretending all is well.

## Contributing

Bug reports and pull requests are welcome. Please run the tests first:

```sh
python3 -m unittest discover -s tests -v
shellcheck install.sh uninstall.sh
```

New checks are welcome when they use an official public source and produce a finding with a concrete fix.

## Security

Found a security problem in php-security-watch itself? Please read [SECURITY.md](SECURITY.md) and
report it privately.

## License

[MIT](LICENSE) © 2026 Zoaftware
