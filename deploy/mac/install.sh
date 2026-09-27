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
# Layout:
#   /Library/Application Support/keyring/            root:_keyring 750
#     rules.json                                     root:_keyring 640  (the service cannot change its rules)
#     admin.pw                                       root:_keyring 640  (dashboard password hash)
#     data/                                          _keyring 700
#       keys.json, access.json, keymeta.json,
#       usage.json, audit.log, service.log           _keyring 600
#
# Running it again upgrades the binary and restarts the service. It never
# changes existing keys or logs, the network settings in rules.json, or a
# dashboard password that is already set.
set -eu

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
usage() { echo "usage: sudo sh install.sh KEYRING_BINARY [--listen IP:PORT --allow IP]" >&2; exit 2; }
BIN_SRC=${1:-}
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || usage
shift
LISTEN= SOURCE=
while [ $# -gt 0 ]; do
	case "$1" in
	--listen) [ $# -ge 2 ] || usage; LISTEN=$2; shift 2 ;;
	--allow) [ $# -ge 2 ] || usage; SOURCE=$2; shift 2 ;;
	*) usage ;;
	esac
done

NAME=_keyring
LABEL=org.gitmoot.keyring
DIR="/Library/Application Support/keyring"
DATA="$DIR/data"
BIN=/usr/local/libexec/keyring
PLIST=/Library/LaunchDaemons/$LABEL.plist
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

# 2. The binary: owned by root, so the service cannot rewrite itself.
install -d -m 755 -o root -g wheel /usr/local/libexec
install -m 755 -o root -g wheel "$BIN_SRC" "$BIN"

# 3. Rules (root-owned, readable by the service) and data (the service's own).
install -d -m 750 -o root -g "$NAME" "$DIR"
install -d -m 700 -o "$NAME" -g "$NAME" "$DATA"
if [ ! -f "$DIR/rules.json" ]; then
	cat >"$DIR/rules.json" <<EOF
{
  "listen": "$LISTEN",
  "allow_sources": ["$SOURCE"],
  "audit_log": "$DATA/audit.log",
  "access_file": "$DATA/access.json"
}
EOF
	if [ ! -e "$DATA/access.json" ]; then
		printf '{\n  "services": {},\n  "roles": {}\n}\n' >"$DATA/access.json"
	fi
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
"$BIN" enable-dashboard --config "$DIR/rules.json"
"$BIN" admin-password --config "$DIR/rules.json" --if-missing
sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json"
# launchd creates the service log with mode 644 whatever the Umask says.
[ -f "$DATA/service.log" ] || : >"$DATA/service.log"
chown "$NAME:$NAME" "$DATA/service.log"
chmod 600 "$DATA/service.log"

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
  <key>StandardErrorPath</key><string>$DATA/service.log</string>
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

# 5. Check.
launchctl print "system/$LABEL" | grep -E '^[[:space:]]*(state|pid) =' || true
ls -la "$DIR" "$DATA"
# The user who ran sudo stands for every other account on this Mac.
U=${SUDO_USER:-}
if [ -n "$U" ] && [ "$U" != root ]; then
	if sudo -u "$U" test -r "$DIR/rules.json" || sudo -u "$U" test -r "$DATA" || sudo -u "$U" test -w "$BIN" ||
		sudo -u "$U" test -r "$DIR/admin.pw"; then
		echo "FAILED: $U can read the keyring's files or change its binary" >&2
		exit 1
	fi
	echo "$U cannot read the rules, password or data, or change the binary: ok"
else
	echo "run from a normal account with sudo to check what other users can read"
fi
ADMIN=$(sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json" | sed -n 's/^dashboard: //p')
if [ -n "$ADMIN" ]; then
	code=$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN/login" || true)
	echo "dashboard $ADMIN/login answers $code (want 200)"
fi
tail -n 3 "$DATA/service.log" 2>/dev/null || true
