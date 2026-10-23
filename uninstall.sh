#!/bin/sh
# Remove php-security-watch.
#
#   sudo ./uninstall.sh           remove the program and its timer or cron entry; keep config and reports
#   sudo ./uninstall.sh --purge   also delete /etc/php-security-watch.conf and /var/lib/php-security-watch
#
# It only removes what install.sh created. Nothing it changed on the server (security updates it
# installed in fix mode, services it restarted) is undone, because those are the fixes.
set -eu

BIN=/usr/local/sbin/php-security-watch
CONF=/etc/php-security-watch.conf
STATE=/var/lib/php-security-watch
UNIT_DIR=/etc/systemd/system
CRON_FILE=/etc/cron.d/php-security-watch
ALPINE_CRONTAB=/etc/crontabs/root
MARK='# php-security-watch'
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; exit 1 ;;
    esac
done

say() { printf '%s\n' "php-security-watch: $*"; }
[ "$(id -u)" -eq 0 ] || { say "run it as root (sudo ./uninstall.sh)"; exit 1; }

if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT_DIR/php-security-watch.timer" ]; then
    systemctl disable --now php-security-watch.timer >/dev/null 2>&1 || true
    systemctl stop php-security-watch.service >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/php-security-watch.timer" "$UNIT_DIR/php-security-watch.service"
    systemctl daemon-reload
    systemctl reset-failed php-security-watch.service >/dev/null 2>&1 || true
    say "removed the systemd timer"
fi

if [ -f "$CRON_FILE" ]; then
    rm -f "$CRON_FILE"
    say "removed $CRON_FILE"
fi

if [ -f "$ALPINE_CRONTAB" ] && grep -q "$MARK" "$ALPINE_CRONTAB"; then
    grep -v "$MARK" "$ALPINE_CRONTAB" > "$ALPINE_CRONTAB.tmp" || true
    cat "$ALPINE_CRONTAB.tmp" > "$ALPINE_CRONTAB"
    rm -f "$ALPINE_CRONTAB.tmp"
    say "removed the line from $ALPINE_CRONTAB"
fi

if [ -f "$BIN" ]; then
    rm -f "$BIN"
    say "removed $BIN"
fi

if [ "$PURGE" -eq 1 ]; then
    rm -f "$CONF" "$CONF.new"
    rm -rf "$STATE"
    say "deleted the config and every saved report (--purge)"
else
    if [ -f "$CONF" ]; then
        say "kept your config $CONF"
    fi
    if [ -d "$STATE" ]; then
        say "kept the reports in $STATE"
    fi
    if [ -f "$CONF" ] || [ -d "$STATE" ]; then
        say "run again with --purge to delete them too"
    fi
fi
say "uninstalled"
