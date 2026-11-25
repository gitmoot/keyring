# Bitcoin PSBT signing (test networks)

A sign-only service with `"auth": "bitcoin-psbt-sign"` holds an imported
Bitcoin key and signs the inputs of a PSBT that belong to it. The key never
leaves keyring: an agent sends a PSBT and gets it back signed; it never sees
the key, and neither does anyone opening the dashboard.

Phase 1 signs on **regtest, testnet and signet only**. A service with
`"network": "mainnet"` is refused when the config is loaded. Mainnet is phase
2: it will require the per-grant limits below.

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

- `network`: `regtest`, `testnet` or `signet` (`mainnet` is refused in phase 1).
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

Both limits are optional on test networks and will be required on mainnet in
phase 2. The dashboard grant form shows them for bitcoin services.

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
  "fee_sats": 5000
}
```

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
`"bitcoin": {"network", "txid", "inputs", "external_sats", "fee_sats"}` —
never the PSBT or the key. The service page shows the watch-only side
(fingerprint, output descriptors with the account xpubs, first addresses) and
a table of the recent signatures read from the audit log.

## Phase 2

Mainnet: config validation will accept `"network": "mainnet"` only with both
per-grant limits set.
