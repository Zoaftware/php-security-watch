#!/bin/sh
# Install php-security-watch: the program, its config and a nightly timer (systemd) or cron entry.
# https://github.com/Zoaftware/php-security-watch - MIT License
#
#   sudo ./install.sh [--mode report|fix] [--email you@example.com] [--webhook URL] [--smtp-url smtps://host:465]
#                     [--time 03:00] [--timezone Area/City] [--no-timer] [--run-now] [--deps]
#
# Safe to run again: it upgrades the program and never overwrites an existing config
# (a new example is written next to it as php-security-watch.conf.new).
set -eu

PREFIX=/usr/local/sbin
BIN="$PREFIX/php-security-watch"
CONF=/etc/php-security-watch.conf
STATE=/var/lib/php-security-watch
UNIT_DIR=/etc/systemd/system
CRON_FILE=/etc/cron.d/php-security-watch
ALPINE_CRONTAB=/etc/crontabs/root
MARK='# php-security-watch'

MODE=""
EMAIL=""
WEBHOOK=""
SMTP_URL=""
RUN_TIME="03:00"
TZONE=""
NO_TIMER=0
RUN_NOW=0
DEPS=0

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

say() { printf '%s\n' "php-security-watch: $*"; }
die() { printf '%s\n' "php-security-watch: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="${2:-}"; shift 2 ;;
        --email) EMAIL="${2:-}"; shift 2 ;;
        --webhook) WEBHOOK="${2:-}"; shift 2 ;;
        --smtp-url) SMTP_URL="${2:-}"; shift 2 ;;
        --time) RUN_TIME="${2:-}"; shift 2 ;;
        --timezone) TZONE="${2:-}"; shift 2 ;;
        --no-timer) NO_TIMER=1; shift ;;
        --run-now) RUN_NOW=1; shift ;;
        --deps) DEPS=1; shift ;;
        -h|--help) usage 0 ;;
        *) printf 'Unknown option: %s\n\n' "$1" >&2; usage 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run it as root (sudo ./install.sh)"
case "$MODE" in ""|report|fix) ;; *) die "--mode must be report or fix" ;; esac
case "$RUN_TIME" in [0-2][0-9]:[0-5][0-9]) ;; *) die "--time must look like 03:00" ;; esac
if [ -n "$TZONE" ] && [ ! -e "/usr/share/zoneinfo/$TZONE" ]; then
    die "unknown time zone $TZONE (see /usr/share/zoneinfo)"
fi

HERE=$(cd "$(dirname "$0")" && pwd)
[ -f "$HERE/php-security-watch" ] || die "run it from the folder that holds the php-security-watch program"

# Python 3.6+ (RHEL 8 has /usr/libexec/platform-python even without python3)
find_python() {
    for p in python3 /usr/bin/python3 /usr/libexec/platform-python /usr/local/bin/python3; do
        if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
            command -v "$p"
            return 0
        fi
    done
    return 1
}

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -q >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 ca-certificates iproute2
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3 ca-certificates iproute dnf-plugins-core || dnf install -y -q python3 ca-certificates iproute
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q python3 ca-certificates iproute yum-utils
    elif command -v apk >/dev/null 2>&1; then
        apk add -q --no-cache python3 ca-certificates iproute2
    elif command -v zypper >/dev/null 2>&1; then
        zypper -n -q install python3 ca-certificates iproute2
    else
        die "no supported package manager to install the dependencies"
    fi
}

if [ "$DEPS" -eq 1 ]; then
    say "installing python3, ca-certificates and ss"
    install_deps
fi

PY=$(find_python) || die "Python 3.6 or newer is required. Install python3, or run again with --deps"

# 1. program
mkdir -p "$PREFIX"
sed "1s|^#!.*|#!$PY|" "$HERE/php-security-watch" > "$BIN.tmp"
chmod 0755 "$BIN.tmp"
mv -f "$BIN.tmp" "$BIN"
"$BIN" --version >/dev/null || die "the installed program does not start ($BIN)"
say "installed $BIN ($("$BIN" --version), $PY)"

# 2. config: write it once, never overwrite
set_key() { # set_key KEY VALUE FILE  (replaces the KEY= line, uncommenting it)
    awk -v k="$1" -v v="$2" '
        BEGIN { done = 0 }
        $0 ~ "^#? *" k "=" && !done { print k "=" v; done = 1; next }
        { print }
        END { if (!done) print k "=" v }
    ' "$3" > "$3.tmp" && cat "$3.tmp" > "$3" && rm -f "$3.tmp"
}

umask 077
if [ -f "$CONF" ]; then
    cp "$HERE/php-security-watch.conf.example" "$CONF.new"
    chmod 0600 "$CONF.new"
    say "kept your config $CONF (the new example is $CONF.new)"
    if [ -n "$MODE$EMAIL$WEBHOOK$SMTP_URL" ]; then
        say "note: --mode/--email/--webhook/--smtp-url only fill a new config; edit $CONF to change them"
    fi
else
    cp "$HERE/php-security-watch.conf.example" "$CONF"
    [ -n "$MODE" ] && set_key MODE "$MODE" "$CONF"
    [ -n "$EMAIL" ] && set_key NOTIFY_EMAIL "$EMAIL" "$CONF"
    [ -n "$WEBHOOK" ] && set_key WEBHOOK_URL "$WEBHOOK" "$CONF"
    [ -n "$SMTP_URL" ] && set_key SMTP_URL "$SMTP_URL" "$CONF"
    say "wrote $CONF"
fi
chown root:root "$CONF" 2>/dev/null || true
chmod 0600 "$CONF"
mkdir -p "$STATE/reports"
chmod 0700 "$STATE"
umask 022

# 3. schedule
HOUR=${RUN_TIME%%:*}
MINUTE=${RUN_TIME##*:}
if [ "$NO_TIMER" -eq 1 ]; then
    say "no schedule installed (--no-timer); run it with: $BIN run"
elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    cp "$HERE/systemd/php-security-watch.service" "$UNIT_DIR/php-security-watch.service"
    sed "s|^OnCalendar=.*|OnCalendar=*-*-* $RUN_TIME:00${TZONE:+ $TZONE}|" \
        "$HERE/systemd/php-security-watch.timer" > "$UNIT_DIR/php-security-watch.timer"
    chmod 0644 "$UNIT_DIR/php-security-watch.service" "$UNIT_DIR/php-security-watch.timer"
    systemctl daemon-reload
    if ! systemctl enable --now php-security-watch.timer >/dev/null 2>&1; then
        # systemd older than 235 does not understand a time zone in OnCalendar
        if [ -n "$TZONE" ]; then
            say "this systemd does not support time zones in timers; using the server's local time"
            sed -i "s|^OnCalendar=.*|OnCalendar=*-*-* $RUN_TIME:00|" "$UNIT_DIR/php-security-watch.timer"
            systemctl daemon-reload
            systemctl enable --now php-security-watch.timer >/dev/null
        else
            die "could not enable php-security-watch.timer"
        fi
    fi
    say "timer on: every day at $RUN_TIME${TZONE:+ $TZONE} (systemctl list-timers php-security-watch.timer)"
elif [ -d /etc/cron.d ] && ! command -v apk >/dev/null 2>&1; then
    LINE="$MINUTE $HOUR * * * root $BIN run --quiet"
    if [ -n "$TZONE" ]; then
        printf 'CRON_TZ=%s\n%s\n' "$TZONE" "$LINE" > "$CRON_FILE"
    else
        printf '%s\n' "$LINE" > "$CRON_FILE"
    fi
    chmod 0644 "$CRON_FILE"
    say "cron entry $CRON_FILE: every day at $RUN_TIME${TZONE:+ $TZONE}"
elif [ -f "$ALPINE_CRONTAB" ] || command -v crond >/dev/null 2>&1; then
    touch "$ALPINE_CRONTAB"
    grep -v "$MARK" "$ALPINE_CRONTAB" > "$ALPINE_CRONTAB.tmp" || true
    printf '%s %s * * * %s run --quiet %s\n' "$MINUTE" "$HOUR" "$BIN" "$MARK" >> "$ALPINE_CRONTAB.tmp"
    cat "$ALPINE_CRONTAB.tmp" > "$ALPINE_CRONTAB"
    rm -f "$ALPINE_CRONTAB.tmp"
    if command -v rc-service >/dev/null 2>&1; then
        rc-update add crond default >/dev/null 2>&1 || true
        rc-service crond start >/dev/null 2>&1 || true
    fi
    say "added to $ALPINE_CRONTAB: every day at $RUN_TIME (server time)"
else
    say "no systemd and no cron found; add this to your scheduler: $BIN run --quiet"
fi

if [ "$RUN_NOW" -eq 1 ]; then
    say "first run (it can take a few minutes)"
    "$BIN" run || true
else
    cat <<EOF

Done. Next steps:
  1. Look at the settings:        nano $CONF
  2. Test the alerts:             $BIN test-notify
  3. First run (read-only):       $BIN run --no-notify
  4. See the last result anytime: $BIN status
EOF
fi
