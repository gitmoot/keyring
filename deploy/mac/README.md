# Installing the keyring on the Mac (step #6)

The owner does this at the Mac. It needs `sudo`, which agents cannot use.

Agents on the agent server can log into the Mac as `jerry`, so they could
replace any file in `/tmp` or in `jerry`'s home. Nothing from there may run as
root until you have checked it yourself. The steps below copy the release
into a directory only root can write, and check its SHA-256 there against the
release page shown in your own browser. `install.sh` refuses to run from
anywhere else.

## Install or upgrade

1. **In your own browser** (not through an agent), open the release on
   <https://github.com/gitmoot/keyring/releases>. Check that:
   - it was published by `github-actions`;
   - its commit is on `main`;
   - you have the SHA-256 of `keyring-vX.Y.Z-darwin-arm64.tar.gz`.

2. Get the archive onto the Mac, for example an agent copies it to
   `/tmp/keyring.tar.gz`. It does not matter who copies it; step 3 checks it.

3. At the Mac:

   ```sh
   sudo mkdir -m 700 /var/root/keyring-install
   sudo cp /tmp/keyring.tar.gz /var/root/keyring-install/
   sudo shasum -a 256 /var/root/keyring-install/keyring.tar.gz
   ```

   **Compare the printed hash with step 1. If they differ, stop and delete
   the directory.**

4. If they match:

   ```sh
   sudo tar -xzof /var/root/keyring-install/keyring.tar.gz -C /var/root/keyring-install
   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring
   sudo rm -r /var/root/keyring-install
   ```

`install.sh`:
- creates the hidden group and user `_keyring`, with no shell and no password, so nobody can log in as it;
- installs `/usr/local/libexec/keyring`, owned by root;
- creates `/Library/Application Support/keyring/` with root-owned `rules.json` (network boundary), which the service can read but not change, and `data/`, which only the service can read (keys, `access.json` with services and roles, audit log, service log);
- moves services and roles out of a `rules.json` from before v0.2 into `data/access.json` (`keyring migrate`);
- starts the LaunchDaemon `org.gitmoot.keyring`. It listens on `100.111.92.43:7701` and accepts only the agent server `100.106.218.88`.

It ends by checking that `jerry` can read neither the rules nor the data and cannot change the binary. Running it again upgrades the binary and keeps the existing rules, keys and logs.

5. Check from the agent server: `curl -s http://100.111.92.43:7701/_keyring/health` should print `ok`.

## Day-to-day commands (at the Mac)

```sh
K="sudo -u _keyring /usr/local/libexec/keyring"
D="/Library/Application Support/keyring"
$K set --store "$D/data/keys.json" OPENROUTER_API_KEY   # paste the value; it is not shown
$K list --store "$D/data/keys.json"
sudo nano "$D/rules.json"                               # network boundary, edited as root
sudo nano "$D/data/access.json"                         # services and roles
$K check --config "$D/rules.json" --store "$D/data/keys.json"
sudo launchctl kill SIGHUP system/org.gitmoot.keyring      # apply access or key changes, no restart
sudo launchctl kickstart -k system/org.gitmoot.keyring  # restart after changing rules.json
sudo tail -f "$D/data/audit.log"
```

## Undo

```sh
sudo launchctl bootout system/org.gitmoot.keyring
sudo rm /Library/LaunchDaemons/org.gitmoot.keyring.plist /usr/local/libexec/keyring
# The keys: only when you are sure they are no longer needed.
sudo rm -r "/Library/Application Support/keyring"
sudo dscl . -delete /Users/_keyring && sudo dscl . -delete /Groups/_keyring
```

## What this does not protect against

The keyring can only be as trustworthy as the `main` branch it is built from.
Agents can open and merge pull requests, so a malicious change would have to
get past review and be released. Read the release's changes before an
upgrade.
