# Installing the keyring on the Mac

The owner does this at the Mac. It needs `sudo`, which agents cannot use.

Agents on the agents' server may be able to log into the Mac as a normal user,
so they could replace any file in `/tmp` or in that user's home. Nothing from
there may run as root until you have checked it yourself. The steps below copy
the release into a directory only root can write, and check its SHA-256 there
against the release page shown in your own browser. `install.sh` refuses to
run from anywhere else.

The examples use `192.0.2.10` for the Mac and `192.0.2.20` for the agents'
server; use your own addresses (for example their tailnet IPs).

## Upgrade (one command)

From v0.7.0 on, at the Mac:

```sh
sudo keyring-upgrade
```

It asks GitHub itself (never the agents' server) for the latest release,
refuses it unless a GitHub Actions workflow of this repo (`github-actions`)
published it, refuses an older release than the one installed,
downloads the archive and that release's `SHA256SUMS` from the release page,
refuses the archive unless its SHA-256 matches, and then runs the release's own
`install.sh` from a directory only root can write. It is the check in step 3
below, done for you. To go back to an older release:
`sudo keyring-upgrade --version v0.7.0`. To see what is installed:
`/usr/local/libexec/keyring version`.

If `/usr/local/bin` is not root-only (e.g. Homebrew owns it), `install.sh` does
not add the `keyring-upgrade` shortcut; run `sudo /usr/local/libexec/keyring upgrade`.

## First install (or upgrade by hand)

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
   # First install: say where to listen and which server may connect.
   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring --listen 192.0.2.10:7701 --allow 192.0.2.20
   # Upgrade: the existing rules are kept, so no addresses.
   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring
   sudo rm -r /var/root/keyring-install
   ```

   When no dashboard password is set yet, it asks for one twice (at least 12
   characters; it is not shown).

`install.sh`:
- creates the hidden group and user `_keyring`, with no shell and no password, so nobody can log in as it;
- installs `/usr/local/libexec/keyring`, owned by root;
- creates `/Library/Application Support/keyring/` with root-owned `rules.json` (the network boundary and dashboard address), which the service can read but not change, the service log (the service's file, in root's directory so the service cannot swap it for a link), and `data/`, which only the service can read (keys, `access.json` with services and roles, test results, usage, audit log);
- moves services and roles out of a `rules.json` from before v0.2 into `data/access.json` (`keyring migrate`);
- turns on the dashboard at `http://127.0.0.1:7702`, on this Mac only, and sets its password if none is set (`keyring enable-dashboard`, `keyring admin-password --if-missing`);
- starts the LaunchDaemon `org.gitmoot.keyring`.

It stops, changing nothing further, if `--listen` or `--allow` is invalid, if the access file in `data/` is a link, or if the stored dashboard password is damaged (then set a new one with `keyring admin-password`). It ends by checking that the account you ran `sudo` from can read neither the rules, the password hash nor the data, and cannot change the binary, and that the dashboard answers; if not, it fails. Running it again upgrades the binary and keeps the existing rules, keys, logs and dashboard password.

5. Check from the agents' server: `curl -s http://192.0.2.10:7701/_keyring/health` should print `ok`.

## The dashboard

Open `http://127.0.0.1:7702` in a browser **on the Mac** and log in with the
dashboard password.

### From your other devices (HTTPS, tailnet only)

The installer can also serve it at `https://keyring.example.com` to a list of
your devices, through Caddy running as its own user `_keyringweb`:

1. In Cloudflare, create an API token with **Zone → DNS → Edit** for the
   domain's zone only. Caddy uses it to prove the name to Let's Encrypt (a DNS
   record, removed afterwards) and renews the certificate by itself.
2. Point the name at the Mac's **tailnet** address: an `A` record, DNS only
   (not proxied). Outside the tailnet the address leads nowhere.
3. Run the installer with the name and each device's tailnet IP (Tailscale
   shows them):

   ```sh
   sudo sh /var/root/keyring-install/install.sh /var/root/keyring-install/keyring \
       --https-host keyring.example.com --device 100.64.0.5 --device 100.64.0.6
   ```

   It asks once for the Cloudflare token (not shown) and keeps it in
   `/Library/Application Support/keyring-web/cloudflare.token`, readable only
   by root and `_keyringweb`. `--new-cloudflare-token` replaces it. Running it
   again with other `--device` values replaces the list; an upgrade without
   them keeps it.

Any other client, including every server on the tailnet, is refused before
the login page (403). The keyring decides this from the client address Caddy
passes on, which a client cannot set itself. Leave out devices other people's
code runs on. On macOS a normal user may use port 443 only on all addresses,
so Caddy listens on all of them; the name resolves to the tailnet address, and
anything else reaching the port is refused the same way.

- **Keys:** add, test, replace, mark as leaked or delete keys. A value is typed once and never shown again, not even in part.
- **Access:** which agent may use which service, with methods, paths, a daily limit and an end date; add an agent (its token is shown once), make a new token, or revoke an agent.

It cannot change `rules.json`: where the keyring listens, which server may
connect, the audit log, or the dashboard's own address and password. Those
stay root's. Every change asks for the password and is written to the audit
log without secrets.

Reset the password (this ends every session):

```sh
sudo /usr/local/libexec/keyring admin-password --config "/Library/Application Support/keyring/rules.json"
sudo launchctl kill SIGHUP system/org.gitmoot.keyring
```

## Day-to-day commands (at the Mac)

The dashboard does most of this. From the terminal:

```sh
K="sudo -u _keyring /usr/local/libexec/keyring"
D="/Library/Application Support/keyring"
$K set --store "$D/data/keys.json" OPENROUTER_API_KEY   # paste the value; it is not shown
$K list --store "$D/data/keys.json"
sudo nano "$D/rules.json"                               # network boundary, edited as root
sudo nano "$D/data/access.json"                         # services and roles
$K check --config "$D/rules.json" --store "$D/data/keys.json"
sudo launchctl kill SIGHUP system/org.gitmoot.keyring   # apply access or key changes, no restart
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
get past review and be released. `keyring-upgrade` installs a release any
workflow on `main` published (normally `release.yml`, which builds only tags on
`main`), so read the release's changes before you run it.

Anyone who can run code as your own Mac user while you are logged in to the
dashboard could use the browser session to look at key names and usage; every
change still needs the password.
