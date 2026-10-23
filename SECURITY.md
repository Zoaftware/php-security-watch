# Security policy

## Reporting a vulnerability in php-security-watch

Please **do not open a public issue** for a security problem in this tool.

Use GitHub's private reporting instead: open the
[Security tab](https://github.com/Zoaftware/php-security-watch/security) of this repository and
press **Report a vulnerability**. Include the version (`php-security-watch --version`), your
operating system and the steps to reproduce it.

We answer within 3 working days and aim to publish a fix within 14 days for anything that lets an
attacker run code, read secrets or change the server through this tool.

## Supported versions

Only the latest release gets security fixes. Upgrading keeps your config:
download the new release and run `sudo ./install.sh` again.

## What this tool is not

php-security-watch reports problems in *your* server. A finding it shows you (an old PHP, a flaw in a
library, an exposed file) is not a vulnerability in php-security-watch: fix it on your server, or
report it to the project that owns that software.
