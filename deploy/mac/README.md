# Installing the keyring on the Mac (step #6)

The owner runs these steps at the Mac: they need `sudo`, and agents cannot use
it.

1. Get the binary built from `main` (an agent copies it to `/tmp` on the Mac):
   `keyring-darwin-arm64`.
2. Run:

   ```sh
   sudo sh install.sh /tmp/keyring-darwin-arm64
   ```

   It creates the hidden user `_keyring`. The user has no shell and no password, so nobody can log in as it. The script then installs `/usr/local/libexec/keyring`, owned by root, and creates `/Library/Application Support/keyring/` (mode 700, owned by `_keyring`) with a first `rules.json` that has no services yet. Last, it starts the LaunchDaemon `org.gitmoot.keyring`, listening on `100.111.92.43:7701` and accepting only the agent server `100.106.218.88`.

   The script ends by checking that `jerry` cannot read the directory.

3. Check from the agent server: `curl -s http://100.111.92.43:7701/_keyring/health` should print `ok`.

## Day-to-day commands (at the Mac)

```sh
K="sudo -u _keyring /usr/local/libexec/keyring"
D="/Library/Application Support/keyring"
$K set --store "$D/keys.json" OPENROUTER_API_KEY   # paste the value; it is not shown
$K list --store "$D/keys.json"
$K check --config "$D/rules.json" --store "$D/keys.json"
sudo launchctl kickstart -k system/org.gitmoot.keyring   # restart after changing rules or keys
sudo tail -f "$D/audit.log"
```

To upgrade, run `install.sh` again with the new binary. It keeps the existing rules, keys and logs.

## Undo

```sh
sudo launchctl bootout system/org.gitmoot.keyring
sudo rm /Library/LaunchDaemons/org.gitmoot.keyring.plist /usr/local/libexec/keyring
# The keys: only when you are sure they are no longer needed.
sudo rm -r "/Library/Application Support/keyring"
sudo dscl . -delete /Users/_keyring && sudo dscl . -delete /Groups/_keyring
```
