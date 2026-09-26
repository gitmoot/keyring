#!/bin/sh
# Install or upgrade the keyring on the Mac. The owner runs it at the Mac, from
# a directory only root can write, after checking the release's SHA-256 (see
# README.md):
#
#   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring
#
# Layout:
#   /Library/Application Support/keyring/            root:_keyring 750
#     rules.json                                     root:_keyring 640  (the service cannot change its rules)
#     data/                                          _keyring 700
#       keys.json, audit.log, service.log            _keyring 600
#
# Running it again upgrades the binary and restarts the service; it never
# touches existing rules, keys or logs.
set -eu

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
BIN_SRC=${1:-}
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || { echo "usage: sudo sh install.sh KEYRING_BINARY" >&2; exit 2; }

NAME=_keyring
LABEL=org.gitmoot.keyring
DIR="/Library/Application Support/keyring"
DATA="$DIR/data"
BIN=/usr/local/libexec/keyring
PLIST=/Library/LaunchDaemons/$LABEL.plist
LISTEN=100.111.92.43:7701
SOURCE=100.106.218.88

# 0. Only run code nobody else could have changed. The script and binary must
# be regular files (not symlinks), and they, their directories and EVERY
# directory above them up to / must be owned by root and writable by nobody
# else: otherwise someone could rename a directory after this check.
trusted() {
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
for f in "$0" "$BIN_SRC"; do
	if [ -L "$f" ] || ! [ -f "$f" ] || ! trusted "$f"; then
		echo "refusing: $f must be a regular root-owned file, not writable by group or others." >&2
		echo "Copy the release into a root-only directory first (see README.md)." >&2
		exit 1
	fi
done
for d in "$(cd "$(dirname "$0")" && pwd -P)" "$(cd "$(dirname "$BIN_SRC")" && pwd -P)"; do
	if bad=$(trusted_tree "$d"); then :; else
		echo "refusing: $bad (above $d) must be owned by root and not writable by group or others." >&2
		echo "Copy the release into a root-only directory first (see README.md)." >&2
		exit 1
	fi
done
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
case "$gid" in
'' | *[!0-9]*)
	echo "group $NAME exists without a numeric PrimaryGroupID; fix or delete it (dscl . -delete /Groups/$NAME) and rerun" >&2
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
ugid=$(dscl . -read "/Users/$NAME" PrimaryGroupID 2>/dev/null | awk '{print $2}')
if [ "$ugid" != "$gid" ]; then
	echo "user $NAME has PrimaryGroupID '$ugid', not $gid; fix it (dscl . -create /Users/$NAME PrimaryGroupID $gid) and rerun" >&2
	exit 1
fi

# 2. The binary: owned by root, so the service cannot rewrite itself.
install -d -m 755 -o root -g wheel /usr/local/libexec
install -m 755 -o root -g wheel "$BIN_SRC" "$BIN"

# 3. Rules (root-owned, readable by the service) and data (the service's own).
for old in keys.json audit.log service.log; do
	if [ -e "$DIR/$old" ]; then
		echo "found $DIR/$old from an earlier layout; move it into $DATA/ (owned by $NAME, mode 600) and rerun" >&2
		exit 1
	fi
done
install -d -m 750 -o root -g "$NAME" "$DIR"
install -d -m 700 -o "$NAME" -g "$NAME" "$DATA"
if [ ! -f "$DIR/rules.json" ]; then
	cat >"$DIR/rules.json" <<EOF
{
  "listen": "$LISTEN",
  "allow_sources": ["$SOURCE"],
  "audit_log": "$DATA/audit.log",
  "services": {},
  "roles": {}
}
EOF
	echo "wrote first rules file (no services yet)"
fi
chown "root:$NAME" "$DIR/rules.json"
chmod 640 "$DIR/rules.json"
sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json"

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
if id jerry >/dev/null 2>&1; then
	if sudo -u jerry test -r "$DIR/rules.json" || sudo -u jerry test -r "$DATA" || sudo -u jerry test -w "$BIN"; then
		echo "FAILED: jerry can read the keyring's files or change its binary" >&2
		exit 1
	fi
	echo "jerry cannot read the rules or data, or change the binary: ok"
else
	echo "no user jerry here: access check skipped"
fi
tail -n 3 "$DATA/service.log" 2>/dev/null || true
