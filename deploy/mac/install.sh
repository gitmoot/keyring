#!/bin/sh
# Install or upgrade the keyring on the Mac. The owner runs it at the Mac, from
# a directory only root can write, after checking the release's SHA-256 (see
# README.md):
#
#   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring \
#       --listen 192.0.2.10:7701 --allow 192.0.2.20
#
# --listen (this Mac's address for the agents' server) and --allow (that
# server's address) are needed on the first install only; an upgrade keeps the
# existing rules.
#
# --https-host NAME --device IP [--device IP ...] also serves the dashboard at
# https://NAME to those devices only, through Caddy (keyring-caddy, next to
# the keyring binary) running as _keyringweb. Its certificate comes from Let's
# Encrypt by a DNS challenge; the first time, the script asks for a Cloudflare
# API token that may edit DNS of NAME's zone (--new-cloudflare-token replaces
# it). NAME's DNS record must point at this Mac's tailnet address. An upgrade
# keeps an HTTPS name set earlier.
#
# Layout:
#   /Library/Application Support/keyring/            root:_keyring 750
#     rules.json                                     root:_keyring 640  (the service cannot change its rules)
#     admin.pw                                       root:_keyring 640  (dashboard password hash)
#     service.log                                    _keyring 600       (in root's directory: see step 3)
#     data/                                          _keyring 700
#       keys.json, access.json, keymeta.json,
#       usage.json, audit.log                        _keyring 600
#
# Running it again upgrades the binary and restarts the service. It never
# changes existing keys or logs, the network settings in rules.json, or a
# dashboard password that is already set.
set -eu

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
usage() { echo "usage: sudo sh install.sh KEYRING_BINARY [--listen IP:PORT --allow IP] [--https-host NAME --device IP ... [--new-cloudflare-token]]" >&2; exit 2; }
BIN_SRC=${1:-}
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || usage
shift
LISTEN= SOURCE= HTTPS_HOST= DEVICE_ARGS= NEW_TOKEN=
while [ $# -gt 0 ]; do
	case "$1" in
	--listen) [ $# -ge 2 ] || usage; LISTEN=$2; shift 2 ;;
	--allow) [ $# -ge 2 ] || usage; SOURCE=$2; shift 2 ;;
	--https-host) [ $# -ge 2 ] || usage; HTTPS_HOST=$2; shift 2 ;;
	# Device IPs contain no spaces or quotes (keyring checks them), so a
	# plain word list is safe.
	--device) [ $# -ge 2 ] || usage; case "$2" in *[!0-9a-fA-F.:]*) usage ;; esac; DEVICE_ARGS="$DEVICE_ARGS --device $2"; shift 2 ;;
	--new-cloudflare-token) NEW_TOKEN=1; shift ;;
	*) usage ;;
	esac
done
[ -z "$DEVICE_ARGS" ] || [ -n "$HTTPS_HOST" ] || usage
[ -n "$DEVICE_ARGS" ] || [ -z "$HTTPS_HOST" ] || usage

NAME=_keyring
LABEL=org.gitmoot.keyring
DIR="/Library/Application Support/keyring"
DATA="$DIR/data"
BIN=/usr/local/libexec/keyring
PLIST=/Library/LaunchDaemons/$LABEL.plist
WEB_NAME=_keyringweb
WEB_LABEL=org.gitmoot.keyring-web
WEB="/Library/Application Support/keyring-web"
WEB_BIN=/usr/local/libexec/keyring-caddy
WEB_PLIST=/Library/LaunchDaemons/$WEB_LABEL.plist
if [ -f "$DIR/rules.json" ]; then
	[ -z "$LISTEN$SOURCE" ] || echo "rules.json exists: --listen and --allow ignored (edit rules.json to change them)"
elif [ -z "$LISTEN" ] || [ -z "$SOURCE" ]; then
	echo "first install: give --listen IP:PORT (this Mac) and --allow IP (the agents' server)" >&2
	exit 2
fi

# 0. Only run code nobody else could have changed. The script and binary must
# be regular files (not symlinks), and they, their directories and EVERY
# directory above them up to / must be owned by root and writable by nobody
# else: otherwise someone could rename a directory after this check.
trusted() {
	# An ACL can grant write access that the mode bits do not show, so any ACL
	# entry makes a path untrusted.
	[ "$(ls -lde "$1" | wc -l)" -eq 1 ] || return 1
	set -- $(stat -f '%u %Lp' "$1")
	[ "$1" = 0 ] && [ $(( 0$2 & 022 )) = 0 ]
}
trusted_tree() { # $1: a real directory path (pwd -P)
	d=$1
	while :; do
		trusted "$d" || { echo "$d"; return 1; }
		[ "$d" = / ] && return 0
		d=$(dirname "$d")
	done
}
# Resolve both files to their real paths ONCE, check those, and use only
# those afterwards: a symlink anywhere in the typed path could otherwise be
# swapped after the check. The running script is already open, so only its
# location needs checking.
real_path() { printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd -P)" "$(basename "$1")"; }
SCRIPT_REAL=$(real_path "$0")
BIN_REAL=$(real_path "$BIN_SRC")
for f in "$SCRIPT_REAL" "$BIN_REAL"; do
	if [ -L "$f" ] || ! [ -f "$f" ] || ! trusted "$f"; then
		echo "refusing: $f must be a regular root-owned file, not writable by group or others." >&2
		echo "Copy the release into a root-only directory first (see README.md)." >&2
		exit 1
	fi
	if bad=$(trusted_tree "$(dirname "$f")"); then :; else
		echo "refusing: $bad (above $f) must be owned by root and not writable by group or others." >&2
		echo "Copy the release into a root-only directory first (see README.md)." >&2
		exit 1
	fi
done
BIN_SRC=$BIN_REAL
echo "keyring binary sha256: $(shasum -a 256 "$BIN_SRC" | cut -d' ' -f1)"
# The HTTPS front ships next to the keyring binary; it is installed when an
# HTTPS name is asked for or was set earlier.
WEB_SRC=$(dirname "$BIN_SRC")/keyring-caddy
WANT_WEB=
if [ -n "$HTTPS_HOST" ] || { [ -f "$DIR/rules.json" ] && grep -q '"admin_https"' "$DIR/rules.json"; }; then
	WANT_WEB=1
	if [ -L "$WEB_SRC" ] || ! [ -f "$WEB_SRC" ] || ! trusted "$WEB_SRC"; then
		echo "refusing: $WEB_SRC must be a regular root-owned file next to the keyring binary." >&2
		exit 1
	fi
	echo "keyring-caddy sha256: $(shasum -a 256 "$WEB_SRC" | cut -d' ' -f1)"
fi

# 1. The service user and group. Nobody can log in as it: no shell, no
# password, hidden.
free_id() {
	uids=$(dscl . -list /Users UniqueID | awk '{print $2}')
	gids=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}')
	id=300
	while printf '%s\n%s\n' "$uids" "$gids" | grep -qx "$id"; do id=$((id + 1)); done
	[ "$id" -lt 400 ] || { echo "no free system id below 400" >&2; exit 1; }
	echo "$id"
}
if ! dscl . -read "/Groups/$NAME" >/dev/null 2>&1; then
	gid=$(free_id)
	dscl . -create "/Groups/$NAME"
	dscl . -create "/Groups/$NAME" PrimaryGroupID "$gid"
	dscl . -create "/Groups/$NAME" RealName "Keyring service"
	echo "created group $NAME ($gid)"
fi
gid=$(dscl . -read "/Groups/$NAME" PrimaryGroupID 2>/dev/null | awk '{print $2}')
# Only an id from the range this script allocates: an existing group with
# another id (for example 0, wheel, or 20, staff) was not made here.
case "$gid" in
3[0-9][0-9]) ;;
*)
	echo "group $NAME has PrimaryGroupID '$gid', not one this installer allocates (300-399); delete it (dscl . -delete /Groups/$NAME) and rerun" >&2
	exit 1
	;;
esac
if ! dscl . -read "/Users/$NAME" >/dev/null 2>&1; then
	uid=$(free_id)
	dscl . -create "/Users/$NAME"
	dscl . -create "/Users/$NAME" UniqueID "$uid"
	dscl . -create "/Users/$NAME" PrimaryGroupID "$gid"
	dscl . -create "/Users/$NAME" UserShell /usr/bin/false
	dscl . -create "/Users/$NAME" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$NAME" RealName "Keyring service"
	dscl . -create "/Users/$NAME" Password '*'
	dscl . -create "/Users/$NAME" IsHidden 1
	echo "created user $NAME ($uid)"
fi
uid=$(dscl . -read "/Users/$NAME" UniqueID 2>/dev/null | awk '{print $2}')
case "$uid" in
3[0-9][0-9]) ;;
*)
	echo "user $NAME has UniqueID '$uid', not one this installer allocates (300-399); delete it (dscl . -delete /Users/$NAME) and rerun" >&2
	exit 1
	;;
esac
ugid=$(dscl . -read "/Users/$NAME" PrimaryGroupID 2>/dev/null | awk '{print $2}')
if [ "$ugid" != "$gid" ]; then
	echo "user $NAME has PrimaryGroupID '$ugid', not $gid; fix it (dscl . -create /Users/$NAME PrimaryGroupID $gid) and rerun" >&2
	exit 1
fi

# 1b. The HTTPS front's user: separate from _keyring, so the web server can
# read neither keys nor rules.
make_user() { # $1: name, $2: real name
	if ! dscl . -read "/Groups/$1" >/dev/null 2>&1; then
		id=$(free_id)
		dscl . -create "/Groups/$1"
		dscl . -create "/Groups/$1" PrimaryGroupID "$id"
		dscl . -create "/Groups/$1" RealName "$2"
		echo "created group $1 ($id)"
	fi
	g=$(dscl . -read "/Groups/$1" PrimaryGroupID 2>/dev/null | awk '{print $2}')
	case "$g" in 3[0-9][0-9]) ;; *) echo "group $1 has PrimaryGroupID '$g', not 300-399; delete it and rerun" >&2; exit 1 ;; esac
	if ! dscl . -read "/Users/$1" >/dev/null 2>&1; then
		id=$(free_id)
		dscl . -create "/Users/$1"
		dscl . -create "/Users/$1" UniqueID "$id"
		dscl . -create "/Users/$1" PrimaryGroupID "$g"
		dscl . -create "/Users/$1" UserShell /usr/bin/false
		dscl . -create "/Users/$1" NFSHomeDirectory /var/empty
		dscl . -create "/Users/$1" RealName "$2"
		dscl . -create "/Users/$1" Password '*'
		dscl . -create "/Users/$1" IsHidden 1
		echo "created user $1 ($id)"
	fi
	u=$(dscl . -read "/Users/$1" UniqueID 2>/dev/null | awk '{print $2}')
	case "$u" in 3[0-9][0-9]) ;; *) echo "user $1 has UniqueID '$u', not 300-399; delete it and rerun" >&2; exit 1 ;; esac
	[ "$(dscl . -read "/Users/$1" PrimaryGroupID 2>/dev/null | awk '{print $2}')" = "$g" ] ||
		{ echo "user $1 is not in group $1; fix it and rerun" >&2; exit 1; }
}
[ -z "$WANT_WEB" ] || make_user "$WEB_NAME" "Keyring dashboard HTTPS"

# 2. The binary: owned by root, so the service cannot rewrite itself.
install -d -m 755 -o root -g wheel /usr/local/libexec
install -m 755 -o root -g wheel "$BIN_SRC" "$BIN"

# 3. Rules (root-owned, readable by the service) and data (the service's own).
install -d -m 750 -o root -g "$NAME" "$DIR"
install -d -m 700 -o "$NAME" -g "$NAME" "$DATA"
if [ ! -f "$DIR/rules.json" ]; then
	# First install: write the rules aside with no services yet, and let
	# migrate check them and create the access file (it writes by rename and
	# never through a link the service could plant). They are put in place
	# only if valid, so a mistyped --listen or --allow leaves nothing behind.
	cat >"$DIR/rules.json.new" <<EOF
{
  "listen": "$LISTEN",
  "allow_sources": ["$SOURCE"],
  "audit_log": "$DATA/audit.log",
  "services": {},
  "roles": {}
}
EOF
	if ! "$BIN" migrate --config "$DIR/rules.json.new" --access "$DATA/access.json"; then
		rm -f "$DIR/rules.json.new"
		echo "check --listen (IP:PORT) and --allow (IP), then run this again" >&2
		exit 1
	fi
	mv "$DIR/rules.json.new" "$DIR/rules.json"
	echo "wrote first rules and access files (no services yet)"
fi
chown "root:$NAME" "$DIR/rules.json"
chmod 640 "$DIR/rules.json"
# A rules file from before the split still holds services and roles: move them
# into the access file, which the service owns. On a split rules file this
# changes nothing except making sure the service owns its access file.
"$BIN" migrate --config "$DIR/rules.json" --access "$DATA/access.json"
# The dashboard: loopback only, with a password stored as a root-owned hash.
# An upgrade keeps the dashboard settings and password that are already there.
# shellcheck disable=SC2086 # DEVICE_ARGS is a checked word list
if [ -n "$HTTPS_HOST" ]; then
	"$BIN" enable-dashboard --config "$DIR/rules.json" --https-host "$HTTPS_HOST" $DEVICE_ARGS
else
	"$BIN" enable-dashboard --config "$DIR/rules.json"
fi
"$BIN" admin-password --config "$DIR/rules.json" --if-missing
sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json"
# The service log is in root's directory, not in data/: launchd opens it at
# every start, possibly as root, and in data/ the service could swap it for a
# link to any file. Here only root can add or rename entries. The file itself
# is the service's, mode 600 (launchd would make it 644).
LOG=$DIR/service.log
touch "$LOG"
chown "$NAME:$NAME" "$LOG"
chmod 600 "$LOG"

# 4. Start at boot as _keyring. KeepAlive restarts it until the tailnet
# address is up after boot.
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>$NAME</string>
  <key>GroupName</key><string>$NAME</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string><string>serve</string>
    <string>--config</string><string>$DIR/rules.json</string>
    <string>--store</string><string>$DATA/keys.json</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl enable "system/$LABEL"
launchctl bootstrap system "$PLIST"
sleep 2

# 4b. The HTTPS front: Caddy as _keyringweb, in front of the loopback
# dashboard. It passes the client's address in X-Keyring-Client (replacing any
# the client sent); the keyring serves the listed devices only. A normal user
# may bind port 443 on macOS only on all addresses, so it listens on all; the
# name resolves to the tailnet address only, and other clients get 403.
if [ -n "$WANT_WEB" ]; then
	WEB_HOST=$(sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json" | sed -n 's/^dashboard https: \([^ ]*\) .*/\1/p')
	ADMIN_LISTEN=$(sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json" | sed -n 's|^dashboard: http://||p')
	[ -n "$WEB_HOST" ] && [ -n "$ADMIN_LISTEN" ] || { echo "rules.json has no admin_https" >&2; exit 1; }
	install -o root -g wheel -m 755 "$WEB_SRC" "$WEB_BIN"
	install -d -o root -g "$WEB_NAME" -m 750 "$WEB"
	install -d -o "$WEB_NAME" -g "$WEB_NAME" -m 700 "$WEB/data"
	TOKEN_FILE=$WEB/cloudflare.token
	if [ -n "$NEW_TOKEN" ] || ! [ -s "$TOKEN_FILE" ]; then
		printf 'Cloudflare API token that may edit DNS of %s (not shown): ' "$WEB_HOST"
		stty -echo; IFS= read -r token; stty echo; echo
		[ -n "$token" ] || { echo "no token given" >&2; exit 1; }
		( umask 077; printf '%s' "$token" >"$TOKEN_FILE.new" )
		unset token
		chown "root:$WEB_NAME" "$TOKEN_FILE.new"; chmod 640 "$TOKEN_FILE.new"
		mv "$TOKEN_FILE.new" "$TOKEN_FILE"
	fi
	chown "root:$WEB_NAME" "$TOKEN_FILE"; chmod 640 "$TOKEN_FILE"
	cat >"$WEB/Caddyfile" <<EOF
{
	admin off
	persist_config off
	skip_install_trust
	auto_https disable_redirects
	storage file_system "$WEB/data"
	servers {
		protocols h1 h2
	}
}

https://$WEB_HOST {
	tls {
		dns cloudflare "{file.$TOKEN_FILE}"
		resolvers 1.1.1.1
	}
	reverse_proxy $ADMIN_LISTEN {
		header_up Host {host}
		header_up X-Keyring-Client {remote_host}
	}
}
EOF
	chown "root:$WEB_NAME" "$WEB/Caddyfile"; chmod 640 "$WEB/Caddyfile"
	WEB_LOG=$WEB/caddy.log
	touch "$WEB_LOG"; chown "$WEB_NAME:$WEB_NAME" "$WEB_LOG"; chmod 600 "$WEB_LOG"
	sudo -u "$WEB_NAME" env HOME="$WEB/data" "$WEB_BIN" validate --config "$WEB/Caddyfile" --adapter caddyfile >/dev/null
	cat >"$WEB_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$WEB_LABEL</string>
  <key>UserName</key><string>$WEB_NAME</string>
  <key>GroupName</key><string>$WEB_NAME</string>
  <key>ProgramArguments</key>
  <array>
    <string>$WEB_BIN</string><string>run</string>
    <string>--config</string><string>$WEB/Caddyfile</string>
    <string>--adapter</string><string>caddyfile</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>$WEB/data</string>
    <key>XDG_DATA_HOME</key><string>$WEB/data</string>
    <key>XDG_CONFIG_HOME</key><string>$WEB/data</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardErrorPath</key><string>$WEB_LOG</string>
</dict>
</plist>
EOF
	chown root:wheel "$WEB_PLIST"; chmod 644 "$WEB_PLIST"
	plutil -lint "$WEB_PLIST" >/dev/null
	launchctl bootout "system/$WEB_LABEL" 2>/dev/null || true
	launchctl enable "system/$WEB_LABEL"
	launchctl bootstrap system "$WEB_PLIST"
fi

# 5. Check.
launchctl print "system/$LABEL" | grep -E '^[[:space:]]*(state|pid) =' || true
ls -la "$DIR" "$DATA"
# The user who ran sudo stands for every other account on this Mac.
U=${SUDO_USER:-}
if [ -n "$U" ] && [ "$U" != root ]; then
	if sudo -u "$U" test -r "$DIR/rules.json" || sudo -u "$U" test -r "$DATA" || sudo -u "$U" test -w "$BIN" ||
		sudo -u "$U" test -r "$DIR/admin.pw" || sudo -u "$U" test -r "$WEB/cloudflare.token"; then
		echo "FAILED: $U can read the keyring's files or change its binary" >&2
		exit 1
	fi
	echo "$U cannot read the rules, password or data, or change the binary: ok"
else
	echo "run from a normal account with sudo to check what other users can read"
fi
ADMIN=$(sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json" | sed -n 's/^dashboard: //p')
if [ -n "$ADMIN" ]; then
	code=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "$ADMIN/login" || true)
	if [ "$code" != 200 ]; then
		echo "FAILED: the dashboard $ADMIN/login answers $code, not 200; see $LOG" >&2
		tail -n 5 "$LOG" >&2 || true
		exit 1
	fi
	echo "dashboard $ADMIN/login answers 200: ok"
fi
if [ -n "$WANT_WEB" ]; then
	# The first certificate takes up to a minute or two. From this Mac the
	# answer is 200 if this Mac is a listed device, else 403: either proves
	# TLS with a real certificate, the proxy and the device check.
	i=0 code=000
	while [ $i -lt 24 ]; do
		code=$(curl -s --max-time 10 --resolve "$WEB_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$WEB_HOST/login" || true)
		case "$code" in 200|403) break ;; esac
		i=$((i + 1)); sleep 5
	done
	case "$code" in
	200|403) echo "https://$WEB_HOST/login answers $code from this Mac with a valid certificate: ok" ;;
	*)
		echo "FAILED: https://$WEB_HOST/login answers $code; see $WEB/caddy.log" >&2
		tail -n 5 "$WEB/caddy.log" >&2 || true
		exit 1
		;;
	esac
fi
tail -n 3 "$LOG" 2>/dev/null || true
