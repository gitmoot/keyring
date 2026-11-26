# Bitcoin PSBT signing

A sign-only service with `"auth": "bitcoin-psbt-sign"` holds an imported
Bitcoin key and signs the inputs of a PSBT that belong to it. The key never
leaves keyring: an agent sends a PSBT and gets it back signed; it never sees
the key, and neither does anyone opening the dashboard.

Phase 1 signs on **regtest, testnet and signet**; phase 2 adds **mainnet**,
with required limits, a fee cap and a notification for every signature (see
[Mainnet](#mainnet)).

Keyring signs; it does not finalise, broadcast, pick coins or build
transactions. The caller (for example an inscription tool) does that.

## 1. Import the key

Keys are imported, never generated and never shown. Supported values:

- a BIP32 **master** extended private key (`tprv…` for regtest, testnet and
  signet; depth 0, so its fingerprint is the master fingerprint wallets write
  into PSBTs), or
- a single compressed **WIF** key (`c…` on test networks).

Read the key from stdin (it is refused as an argument, so it does not end up in
shell history or process lists):

```sh
keyring bitcoin-import --config rules.json --store ~/.keyring/keys.json --network regtest BTC_ORD < /path/to/tprv.txt
```

Without a redirect it prompts and reads the key without echo. It refuses an
existing name, a key for another network (`xprv` on regtest, `tprv` on
mainnet), a name a service other than a Bitcoin signing service would use
(see below), and anything else that is not a key, with a fixed message that
never contains the value. It prints what to check in your wallet:

```
stored BTC_ORD
fingerprint: 73c5da0a
network:     regtest
kind:        BIP32 master key
first receive addresses (check them in your wallet):
  m/86'/1'/0'/0/0   p2tr    bcrt1p…
  m/84'/1'/0'/0/0   p2wpkh  bcrt1q…
```

Pasting the key with **Add key** on the dashboard works too. Keyring recognises
`tprv`/`xprv`/WIF values, and any key used by a `bitcoin-psbt-sign` service,
and never offers **Show** for them: the key page shows the fingerprint and
networks instead, and a reveal request is refused (`?error=never-shown`).

**A Bitcoin key is only ever used by a `bitcoin-psbt-sign` service.** Any
other service would send its key upstream as a credential, so keyring refuses
changes in which one would use a stored Bitcoin key: its `key`, a value of
its key pool, an extra header, an OAuth client secret, or the refresh token of
a Workspace account. The refusal reads `service api: BTC_ORD is a Bitcoin key;
it can only be used by a Bitcoin signing service` and nothing is saved. It is
checked wherever settings and keys change together: the dashboard's Connect,
service, key and upload forms, the instance admin API, consent links, and
`keyring set` and `keyring bitcoin-import`, which need `--config` to store a
Bitcoin key. `keyring check` refuses such settings too.

Settings and keys that already hold such a use (written by hand, or stored
before v0.15.3) still load, so one bad credential never stops the keyring or
locks an instance: the service start and a reload log a warning naming the
service and key, an unlocked instance logs it and its status lists the
service (or the Workspace account, `bitcoin_key_refused`) as failing. One
check stands before every outbound use of a stored credential: such a call
is answered 503 with the audit note `bitcoin key refused`, and an OAuth
refresh, a sign-in's code exchange (with a Bitcoin key as client secret) or
a disconnect's revoke (`"revoked": false`, the key is still deleted) is
refused, so nothing goes upstream. Replace or delete the key, or change the
service, to fix it; other changes keep working meanwhile.

## 2. The service

**On the dashboard** (Keys → the key → Connect to a service): the page of a
key whose one value is a Bitcoin key (a key with several values keeps the API
form; paste the settings there) offers a Bitcoin form instead: service name,
network (regtest, testnet or signet), the path templates one per line
(prefilled with BIP86 receive and change, `m/86'/1'/0'/0/*` and
`m/86'/1'/0'/1/*`; add `m/84'/1'/0'/0/*` and `m/84'/1'/0'/1/*` for native
SegWit) and the sighash types (default and all ticked; the others carry the
warning below). For a WIF key the form asks for the script (`p2tr` or
`p2wpkh`) instead of paths. Connect checks the whole access list and that the
key fits the service (network; paths for a tprv, script for a WIF key) before
anything is written, and is audit-logged as `key_connected`.

Or open **Or paste settings** and paste
`{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{…}}`, or the
service as the access file writes it: `{"btc-ord":{…}}`, or the
`"btc-ord": {…}` block below as it is. A `key` in pasted settings must be the
key whose page it is.

The service page (`/services/<name>`) edits the network, paths (or script)
and sighash types the same ways; the edit is audit-logged as
`service_edited` with the names that changed (`bitcoin.paths`,
`bitcoin.sighash`, …). A Bitcoin service stays one. The sats limits are on
each agent's grant (section 3).

**In the access file** (`services` → name):

```json
"btc-ord": {
  "auth": "bitcoin-psbt-sign",
  "key": "BTC_ORD",
  "bitcoin": {
    "network": "regtest",
    "paths": ["m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*", "m/84'/1'/0'/0/*", "m/84'/1'/0'/1/*"],
    "sighash": ["default", "all"]
  }
}
```

- `network`: `mainnet`, `regtest`, `testnet` or `signet`.
- `paths` (tprv keys): the derivation path templates keyring signs for.
  Hardened steps take `'` or `h`. A trailing `/*` means any non-hardened index
  (0 … 2^31-1). The purpose must be `86'` (taproot key path, BIP86: the BIP341
  tweak with no script tree) or `84'` (native SegWit P2WPKH); it decides the
  script. The coin type and account are whatever you list. No two templates
  may share the part before `/*` (`m/86'/1'/0'/0` with `m/86'/1'/0'/0/*`):
  the addresses call names a template by that part.
- `script` (WIF keys instead of `paths`): `p2tr` (BIP86-style key path) or
  `p2wpkh`.
- `sighash` (optional): the sighash types it signs. Default `["default",
  "all"]`. `none`, `single` and their `|anyonecanpay` forms are refused unless
  listed. If you list them, remember the counterparty may change what the
  signature does not commit to, so `external_sats` only describes this PSBT.

No base, identity fields or test path; the key may not be shared with another
service, as for the other sign-only services.

## 3. The grant

Grant the role the service like any other. Two optional limits sit next to
`daily_requests`:

```json
"roles": {
  "ordinals": {
    "token_sha256": "…",
    "access": {
      "btc-ord": {
        "paths": ["/"],
        "daily_requests": 200,
        "bitcoin_max_sats_per_tx": 100000,
        "bitcoin_max_sats_per_day": 1000000
      }
    }
  }
}
```

- `paths`: `/` allows both actions; `/sign-psbt` or `/addresses` allows one.
- `bitcoin_max_sats_per_tx`: the most external sats one PSBT may send.
- `bitcoin_max_sats_per_day`: the most external sats per role and service per
  UTC day. The total is kept next to the key store in a file named after it
  (`keys.json` → `keys.json.bitcoin-spend.json`; in instance mode after `--state`), written atomically after each
  successful signature, so a restart does not reset it. If that file is
  missing a limit cannot be kept: a grant with a per-day limit is then refused
  with 503, and a corrupt or unsafe file is left alone and refused the same way.

Both limits are optional on test networks and required on mainnet (see
[Mainnet](#mainnet)). The dashboard grant form shows them for bitcoin services.

## API

Through the relay (`/<role>/…`) or directly with the role token:

### Sign

`POST /<role>/_keyring/bitcoin/<service>/sign-psbt`

```json
{"psbt": "<base64 PSBT>", "inputs": [0, 2]}
```

`inputs` lists the input indices keyring should sign. Reply (`Cache-Control:
no-store`):

```json
{
  "psbt": "<base64 PSBT with the signatures added>",
  "txid": "<id of the unsigned transaction>",
  "signed": [0, 2],
  "external_sats": 65000,
  "fee_sats": 5000,
  "vbytes": 154
}
```

`vbytes` is a size the finalised transaction is never below (see
[Mainnet](#mainnet)), so `fee_sats / vbytes` is never below its real fee
rate.

Taproot inputs get the key-path signature (`tap_key_sig`), P2WPKH inputs a
partial signature; nothing is finalised. Body up to 4 MiB.

### Addresses

`GET /<role>/_keyring/bitcoin/<service>/addresses?path=m/86'/1'/0'/0&from=0&count=20`

`path` is one of the service's templates without the `/*`; `count` is 1 …
1000 (default 20). For a WIF service the path is `m`. Reply:

```json
{"fingerprint": "73c5da0a", "network": "regtest", "path": "m/86'/1'/0'/0",
 "addresses": [{"index": 0, "path": "m/86'/1'/0'/0/0", "script": "p2tr",
                "public_key": "…", "address": "bcrt1p…"}]}
```

## Rules

Every rule must hold, or the reply is 400 with a fixed reason and nothing is
signed:

1. The PSBT parses and `inputs` is not empty, has no duplicates and every index
   exists.
2. **Every** input (listed or not) has `witness_utxo`, so the amounts and the
   fee are known; no two inputs spend the same output; outputs do not exceed
   inputs. Each amount must be committed by every signature returned: a
   taproot signature without anyonecanpay commits to all of them (BIP341),
   but a P2WPKH signature (BIP143) or a taproot anyonecanpay one commits only
   to its own input's amount. So if the call makes such a signature, every
   other input (listed or not) needs `non_witness_utxo` (the previous
   transaction, matching its outpoint and `witness_utxo`). Sign all of the
   key's inputs in one call: each call counts the PSBT's external sats.
3. Each listed input is not finalised and has a `tap_bip32_derivation`
   (purpose 86) or `bip32_derivation` (purpose 84) with this key's master
   fingerprint, on an allowed path, whose public key is this key's at that
   path, and whose script (BIP86 tweaked key or P2WPKH) equals the
   `witness_utxo` script. Taproot inputs with a script tree or leaf hashes, and
   P2WPKH inputs with redeem or witness scripts, are refused.
4. Each listed input's sighash is on the service list; `single` needs an output
   at the same index.
5. Every output is a standard address script (P2PKH, P2SH, P2WPKH, P2WSH,
   P2TR). An output script itself carries no network, so this is what "an
   address on the service network" can mean: OP_RETURN, bare pubkey, bare
   multisig, unknown witness versions and other non-address scripts are
   refused.
6. `external_sats` = the outputs not proven to be this key's + the fee. An
   output is proven own when it carries derivation info with this fingerprint
   on an allowed path and the derived script equals the output script (change
   to an address of the same key without that info counts as external).
7. `external_sats` is within the grant's per-PSBT and per-day limits. The day
   total counts only after a successful signature.

The reasons name indices and numbers only, for example `input 1 has no
derivation with this key's fingerprint 73c5da0a` or `bitcoin_max_sats_per_tx:
120000 external sats is over the limit of 100000`. A key that does not fit
the service (wrong network, a WIF where paths are set) is 503
`bitcoin key unavailable: …`.

## Audit and dashboard

Each signature writes one audit line with the role, service and
`"bitcoin": {"network", "txid", "inputs", "external_sats", "fee_sats", "vbytes"}` —
never the PSBT or the key. The service page shows the watch-only side
(fingerprint, output descriptors with the account xpubs, first addresses) and
a table of the recent signatures read from the audit log.

## Mainnet

Phase 2 (owner rules, 2026-11-26, #187). Real bitcoin, so on top of every
rule above:

**Setup.**

1. Import a key of its own: `keyring bitcoin-import --config rules.json
   --store keys.json --network mainnet NAME` (an `xprv` or a mainnet WIF). A
   key that also backs a test-network service (the same seed, or the same
   secret as a test WIF) is refused: the dashboard will not create the
   service, the service page warns, and signing answers 503.
2. Set up signature notices (see [Signature notices](#signature-notices)):
   `notify` in `rules.json`, the token stored, the relay's notify listener
   on. A mainnet service without `notify` is refused at load, `check` and
   `SIGHUP`, and signing answers 503 `no owner notification configured`.
   Instance mode has no trusted channel for it, so it refuses mainnet
   services outright.
3. Create the service with `"network": "mainnet"`. Its `paths` may only be
   `m/86'/0'/0'/0/*`, `m/86'/0'/0'/1/*`, `m/84'/0'/0'/0/*`,
   `m/84'/0'/0'/1/*`, and its `sighash` only `default` and `all` (none,
   single and anyonecanpay leave inputs or outputs uncommitted, so a
   signature could outlive the PSBT whose sats were checked); the signer
   refuses the others on mainnet whatever the list says. A service never
   moves between mainnet and the test networks (the dashboard refuses the
   edit), so grants never carry across; make a new service instead.
4. Grant one role at a time, with both limits and the typed confirmation.

**Ceilings and required limits.** Every grant on a mainnet service sets both
`bitcoin_max_sats_per_tx` (1 … 200,000) and `bitcoin_max_sats_per_day`
(1 … 1,000,000), the per-PSBT one at most the daily one. A config without
them is refused at load, `check` and `SIGHUP`. Project grants have no limits,
so they never reach a mainnet service: only the role's own grant does, and
switching it off revokes that service alone.

**Typed confirmation.** On the dashboard, creating a mainnet grant, renewing
one that has ended or raising either sats limit, and approving a request for
a mainnet service (which asks for both limits), take the service name and
the daily limit typed again exactly; otherwise nothing is saved.

**Fee cap.** A mainnet PSBT whose fee is above 50,000 sats or whose fee rate
is above 200 sat/vB is refused. The rate is the fee over `vbytes`, a size the
finalised transaction is never below, so the computed rate is never below
the real one: the non-witness part of the transaction exactly, the inputs
keyring signs at their smallest witness (a 64-byte taproot signature, 65
with sighash `all`; a P2WPKH one with the shortest DER signature and the
33-byte key), and every other input with an empty witness and script sig,
even when the PSBT carries it finalised. Keyring's signature does not commit
to another input's witness, so that witness could be stripped or replaced
after signing; padding it never lowers the rate keyring computes.

The check is conservative: the real rate is at most the one checked, and
lower by a lot when other inputs carry large witnesses (an inscription
reveal). Such a PSBT may need a lower fee rate on the inputs keyring signs,
or the keyring inputs signed in a transaction of their own. Inputs keyring
does not sign may be of any kind.

### Signature notices

Every mainnet signature sends the owner a notice through the channel the
owner picked in `rules.json` (`notify`), for example `keyring: mainnet
signature by phobos on btc-main: txid …, 65000 sats external, fee 5000
sats, 32.5 sat/vB`. A refusal or a test network sends none. It starts once
the signature and its day total are kept, before the reply is written, runs
in the background for at most 30 seconds (the relay's gram command gets 20), and a failure is written to the
audit log (`"method":"NOTIFY"`); it never delays or fails the signature.

The channel is a setting so other channels can be offered later; for now
**Gram** is the only one. The keyring's Mac cannot run `herdr`, so the
keyring POSTs `{"text": "…"}` with `Authorization: Bearer <token>` over the
tailnet to a relay's notify listener, which runs `herdr gram send --from
keyring <text>` on its host.

On the relay host (as root; see [relay](relay.md#signature-notices)):

```sh
(umask 077; keyring new-token | awk '/^token:/ {print $2}' > /etc/keyring/notify.token)  # root-owned, mode 600
# add to the relay's ExecStart (and the sandbox changes in relay.md), then restart it:
#   --notify-listen 100.106.218.88:7702 --notify-allow 100.111.92.43 \
#   --notify-token-file /etc/keyring/notify.token --gram-command /root/.local/bin/herdr
```

Copy the file's one line to the Mac over a private channel for the next
step; do not paste it anywhere else.

On the keyring's Mac (after upgrading to a release with `notify`):

1. Store the same token, pasted on stdin (not echoed), or with Add key on
   the dashboard:

   ```sh
   sudo -u _keyring /usr/local/libexec/keyring set \
     --store "/Library/Application Support/keyring/data/keys.json" KEYRING_NOTIFY_TOKEN
   ```

   It is never shown again, not even on request, and no service may use it.
2. Add to `/Library/Application Support/keyring/rules.json` (root-owned,
   `sudo nano`):

   ```json
   "notify": {"channel": "gram", "url": "http://100.106.218.88:7702/notify", "token_key": "KEYRING_NOTIFY_TOKEN"}
   ```

   `channel` must be one of the supported channels (`gram`); `url` is https,
   or plain http to a tailnet or loopback IP only; `token_key` is a key
   name without a `.part`.
3. Check, then reload:

   ```sh
   sudo -u _keyring /usr/local/libexec/keyring check \
     --config "/Library/Application Support/keyring/rules.json" \
     --store "/Library/Application Support/keyring/data/keys.json"
   sudo launchctl kill SIGHUP system/org.gitmoot.keyring
   ```
4. On the dashboard, open any Bitcoin service: the **Signature notices** card
   shows the channel, the relay notify URL and the token key, and **Send
   test notice** (password asked, audited as `signature_notice_test`) sends
   one through it and shows whether the relay took it.

See [configuration](configuration.md#notify).
