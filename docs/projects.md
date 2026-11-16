# Projects: a client's services, paused or expired together

Services that belong to one client or engagement can be grouped in a **project** (#111). A service joins one with `"project": "acme"` (lowercase letters, digits and `-`, like a service name); set it on the service's edit page in the dashboard, or in pasted settings. A project exists as soon as a service names it. Services without a project behave exactly as before, and existing access files need no change.

Project settings, all optional, go in the access file under `projects`:

```json
"projects": {
  "acme": {"paused": true, "expires": "2027-03-31T00:00:00Z", "client_owned": true}
}
```

- `paused`: every call to the project's services is refused with **403 `project_paused: project acme is paused`**, before any key is used, any quota spent or anything sent. Keys and agent access stay as they are; removing `paused` restores everything.
- `expires`: from that moment the project counts as paused (`project acme is expired`) until the date is moved or removed.
- `client_owned`: marks the project's keys as belonging to the client. It changes no call; the project page then shows a handover list.

In the dashboard, the **Projects** tab lists every project with its state, and each project's page shows its services (key, API, last use, calls today) and the agents with access. From that page, with the password:
- **Settings:** pause or resume, set or clear an end date (from the start of that day, UTC, the project counts as paused), and mark the keys client-owned. Saved as `project_changed` in the audit log with what changed.
- **Give an agent access to the project:** in one step, with chosen methods, paths, a daily limit (applied to each service separately) and an end date. Without "Include services added to this project later" it writes an ordinary grant for each service the project has now (`access_changed` audit line per service); with it, one grant covers the whole project as it changes (`project_access_granted`).
- **Remove an agent's access to the project:** takes away its access to every service in the project, and its whole-project grant, in one step, and only those; its access elsewhere stays. One `access_revoked` audit line per service, and `project_access_revoked` for a whole-project grant.
- **Handover list** (client-owned projects): each project key with when it was added here and when it was last replaced, for rotating them when the engagement ends. Values are never shown; "unknown" means the key predates the dashboard keeping that date (keys added with `keyring set` also show unknown).

A whole-project grant is stored on the role in the access file:

```json
"roles": {"acme": {"token_sha256": "…", "access": {}, "projects": {"acme": {"methods": ["GET"], "paths": ["/"]}}}}
```

A role's own grant for a single service takes precedence over its grant for that service's project, so one service can be narrowed (or widened). Moving a service into or out of a project changes which whole-project grants reach it; the edit's audit line names agents that gained or lost access that way (`access_gained_by`, `access_lost_by`). The agent and access pages show access that comes through a project. An agent can ask for a whole project with `keyring request ... --project acme` (with or without `--service`); approving it gives full access to the whole project, services added later included. To give less, decline and use the project page.

The Keys and Agents pages filter by project: "Personal" is everything outside a project, and the filter is kept by search, status filters and sorting. Each key shows its project.

The dashboard Test button refuses a stopped project the same way. Every audit line for a project's service carries `"project"`. A `projects` entry without services is allowed, so removing a project's last service never blocks. Apply changes with a reload (SIGHUP), as for any access-file edit. A keyring older than v0.14.5 refuses an access file that uses `project` or `projects` (on a service, at the top level, or on a role), so take them out before downgrading.
