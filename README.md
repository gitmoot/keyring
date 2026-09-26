# keyring

Keeps API keys on a separate machine. Agents call APIs **through** the keyring,
so a key never reaches the machine where agents run.

Status: design only. Nothing is built yet.

## Why

On the agent server every agent runs as root, so any agent can read every key
in `/root/.env`, and keys leak by accident into chats, PRs and logs. Moving
the keys to another machine means there is nothing on the agent server to
read or leak.

## How it works

```
agent server                           keyring machine (tailnet only)
┌──────────────────────┐               ┌───────────────────────────────┐
│ agent                │               │ keyring service               │
│   │ POST /openrouter/…               │  1. who is calling? (role)    │
│   ▼                  │   tailnet     │  2. allowed? (key, path, cap) │
│ local relay :7700 ───┼──────────────▶│  3. add the key, call the API │
│   (adds role token)  │               │  4. log it, return the answer │
└──────────────────────┘               └──────────────┬────────────────┘
                                                      ▼
                                             OpenRouter, Apple, …
```

Three ways to use a key:

| Mode  | What the agent does | Key leaves the keyring? |
|-------|---------------------|-------------------------|
| proxy | Sends the request without a key; the keyring adds it | never |
| sign  | Asks for a short-lived token (Apple JWTs) | only the token, minutes |
| run   | Asks for the raw key for one command | yes (last resort, logged) |

Per role: which keys, which API paths, a spending cap, and an expiry. Every
call is logged without the key. Rotating a key is one change on the keyring
machine.

## Limits

- Each role's token sits on the agent server, so a misbehaving root agent can
  use another role's access. It still cannot read the keys, and every call is
  logged and revocable.
- If the keyring machine is off or asleep, API calls fail.
