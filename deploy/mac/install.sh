#!/bin/sh
# Install or upgrade the keyring on the Mac. Run it yourself at the Mac:
#
#   sudo sh install.sh ./keyring-darwin-arm64
#
# It creates the hidden user _keyring (no shell, no password, so nobody can
# log in as it), puts the binary in /usr/local/libexec, creates the private
# data directory, writes a first rules file if there is none, and starts the
# service at boot as _keyring. Running it again upgrades the binary and
# restarts the service; it never touches existing rules, keys or logs.
set -eu

BIN_SRC=${1:-}
[ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ] || { echo "usage: sudo sh install.sh KEYRING_BINARY" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

NAME=_keyring
LABEL=org.gitmoot.keyring
DIR="/Library/Application Support/keyring"
BIN=/usr/local/libexec/keyring
PLIST=/Library/LaunchDaemons/$LABEL.plist
LISTEN=${KEYRING_LISTEN:-100.111.92.43:7701}
SOURCE=${KEYRING_SOURCE:-100.106.218.88}

# 1. The service user.
if ! dscl . -read "/Users/$NAME" >/dev/null 2>&1; then
	uids=$(dscl . -list /Users UniqueID | awk '{print $2}')
	gids=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}')
	id=300
	while printf '%s\n%s\n' "$uids" "$gids" | grep -qx "$id"; do id=$((id + 1)); done
	[ "$id" -lt 400 ] || { echo "no free system id below 400" >&2; exit 1; }
	dscl . -create "/Groups/$NAME"
	dscl . -create "/Groups/$NAME" PrimaryGroupID "$id"
	dscl . -create "/Groups/$NAME" RealName "Keyring service"
	dscl . -create "/Users/$NAME"
	dscl . -create "/Users/$NAME" UniqueID "$id"
	dscl . -create "/Users/$NAME" PrimaryGroupID "$id"
	dscl . -create "/Users/$NAME" UserShell /usr/bin/false
	dscl . -create "/Users/$NAME" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$NAME" RealName "Keyring service"
	dscl . -create "/Users/$NAME" Password '*'
	dscl . -create "/Users/$NAME" IsHidden 1
	echo "created user $NAME ($id)"
fi

# 2. The binary: owned by root, so the service cannot rewrite itself.
install -d -m 755 -o root -g wheel /usr/local/libexec
install -m 755 -o root -g wheel "$BIN_SRC" "$BIN"

# 3. The private data directory.
install -d -m 700 -o "$NAME" -g "$NAME" "$DIR"
if [ ! -f "$DIR/rules.json" ]; then
	cat >"$DIR/rules.json" <<EOF
{
  "listen": "$LISTEN",
  "allow_sources": ["$SOURCE"],
  "audit_log": "$DIR/audit.log",
  "services": {},
  "roles": {}
}
EOF
	chown "$NAME:$NAME" "$DIR/rules.json"
	chmod 600 "$DIR/rules.json"
	echo "wrote first rules file (no services yet)"
fi
sudo -u "$NAME" "$BIN" check --config "$DIR/rules.json"

# 4. Start at boot as _keyring. KeepAlive restarts it if the tailnet address
# is not up yet at boot.
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
    <string>--store</string><string>$DIR/keys.json</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardErrorPath</key><string>$DIR/service.log</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 2

# 5. Check.
launchctl print "system/$LABEL" | grep -E '^\s*(state|pid) =' || true
echo "--- $DIR:"
ls -la "$DIR"
if sudo -u jerry cat "$DIR/rules.json" >/dev/null 2>&1; then
	echo "WARNING: jerry can read $DIR" >&2
	exit 1
fi
echo "jerry cannot read $DIR: ok"
tail -n 3 "$DIR/service.log" 2>/dev/null || true
