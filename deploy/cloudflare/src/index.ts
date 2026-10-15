// Per-person keyrings on Cloudflare Containers (gitmoot/keyring#46, option B1).
//
// One Durable Object per person supervises one container that runs the
// unchanged keyring binary as `keyring instance --container`. The Durable
// Object keeps the sealed state, the daily counts and its own tokens; the
// data key that opens the state is derived from a Worker secret and a
// per-instance salt, so deleting the Durable Object's storage makes every
// copy of the state unreadable. The container's disk holds nothing.
//
// Routes (all on one Worker):
//   /p/<id>/<service>/<path>   proxy for the router: X-Keyring-Caller + X-Keyring-Token
//   /admin/instances...        admin for the router: X-Keyring-Caller + Bearer ADMIN_TOKEN
//   /connect/<id>/c/<link>     consent link pages for the person (public)
//   /connect/callback          OAuth callback for the person (public; one URL for every instance)
import { DurableObject } from "cloudflare:workers";

export interface Env {
	KEYRING: DurableObjectNamespace<KeyringInstance>;
	/** https origin of this Worker, e.g. https://keyring.example.com */
	PUBLIC_BASE: string;
	/** The services every new instance starts with (a JSON var). */
	SERVICES_TEMPLATE: Template | string;
	/** Secret: base64 of 32 random bytes; derives every instance's data key. */
	MASTER_KEY: string;
	/** Secret: the router's proof, sent as X-Keyring-Caller. */
	CALLER_SECRET: string;
	/** Secret: the router's admin token, sent as Authorization: Bearer. */
	ADMIN_TOKEN: string;
	/** Secret (optional): JSON {"KEY_NAME": "value"}, OAuth client secrets put in every instance. */
	OAUTH_CLIENT_SECRETS?: string;
}

/** The services every instance has, and the router role's access to each. */
interface Template {
	services: Record<string, Record<string, unknown>>;
	access: Record<string, Record<string, unknown>>;
}

const CALLER_HEADER = "X-Keyring-Caller";
const ROLE = "router";
const PORT_PROXY = 8080;
const PORT_PAGES = 8081;
const PORT_CONSENT_API = 8082;
const PORT_ADMIN = 8090;
/** Stop a container after this long without a call (and no open link). */
const IDLE_MS = 10 * 60 * 1000;
/** How often a running container's daily counts are saved. */
const TICK_MS = 60 * 1000;
/** A sign-in may finish this long after its link expires (keyring signInTTL). */
const SIGN_IN_MS = 10 * 60 * 1000;
const INSTANCE_COOKIE = "__Host-keyring-instance";

// ---------- helpers ----------

const enc = new TextEncoder();

function b64(bytes: ArrayBuffer | Uint8Array): string {
	const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let s = "";
	for (const b of u) s += String.fromCharCode(b);
	return btoa(s);
}

function unb64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomToken(): string {
	return b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(s: string): Promise<string> {
	return hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

/** Constant-time comparison of two secrets (by their SHA-256). */
async function secretEquals(got: string | null, want: string): Promise<boolean> {
	if (!got || !want) return false;
	const [a, b] = await Promise.all([
		crypto.subtle.digest("SHA-256", enc.encode(got)),
		crypto.subtle.digest("SHA-256", enc.encode(want)),
	]);
	return crypto.subtle.timingSafeEqual(a, b);
}

function json(status: number, body: unknown, headers: HeadersInit = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
	});
}

const ID = /^[a-f0-9]{32}$/;

// ---------- Worker ----------

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const parts = url.pathname.split("/");
		// Public consent routes: the person's browser, no router proof.
		if (parts[1] === "connect") {
			if (url.pathname === "/connect/callback") {
				const id = cookie(request, INSTANCE_COOKIE);
				if (!id || !ID.test(id)) return page(400, "This sign-in has expired. Ask for a new link.");
				return stub(env, id).fetch(internal(request, "/_pages/connect/callback" + url.search));
			}
			const id = parts[2];
			if (!ID.test(id ?? "") || parts[3] !== "c") return page(404, "Not found.");
			return stub(env, id).fetch(internal(request, "/_pages/connect/" + parts.slice(3).join("/") + url.search));
		}
		// Everything else is for the router only.
		if (!(await secretEquals(request.headers.get(CALLER_HEADER), env.CALLER_SECRET))) {
			return json(401, { error: "caller proof required" });
		}
		if (parts[1] === "p") {
			const id = parts[2];
			if (!ID.test(id ?? "")) return json(404, { error: "unknown keyring" });
			return stub(env, id).fetch(internal(request, "/_proxy/" + parts.slice(3).join("/") + url.search));
		}
		if (parts[1] === "admin" && parts[2] === "instances") {
			const auth = request.headers.get("authorization") ?? "";
			if (!auth.startsWith("Bearer ") || !(await secretEquals(auth.slice(7), env.ADMIN_TOKEN))) {
				return json(401, { error: "admin token required" });
			}
			return admin(request, env, parts.slice(3));
		}
		return json(404, { error: "not found" });
	},
} satisfies ExportedHandler<Env>;

function stub(env: Env, id: string): DurableObjectStub<KeyringInstance> {
	return env.KEYRING.get(env.KEYRING.idFromName(id));
}

/** A copy of request for the Durable Object, at path, without the router proof. */
function internal(request: Request, path: string): Request {
	const headers = new Headers(request.headers);
	headers.delete(CALLER_HEADER);
	return new Request("https://do" + path, {
		method: request.method,
		headers,
		body: request.body,
		redirect: "manual",
	});
}

function cookie(request: Request, name: string): string | null {
	for (const part of (request.headers.get("cookie") ?? "").split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === name) return v.join("=");
	}
	return null;
}

function page(status: number, message: string): Response {
	return new Response(`<!doctype html><meta charset="utf-8"><title>keyring</title><p>${message}</p>`, {
		status,
		headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" },
	});
}

async function admin(request: Request, env: Env, rest: string[]): Promise<Response> {
	const m = request.method;
	if (rest.length === 0 && m === "POST") {
		const body = (await request.json().catch(() => ({}))) as { label?: unknown };
		const id = hex(crypto.getRandomValues(new Uint8Array(16)).buffer);
		const out = await stub(env, id).create(id, typeof body.label === "string" ? body.label.slice(0, 100) : "");
		if ("error" in out) return json(out.status, { error: out.error });
		return json(201, { keyring_id: id, keyring_base: `${env.PUBLIC_BASE}/p/${id}`, role_token: out.role_token });
	}
	const id = rest[0];
	if (!ID.test(id ?? "")) return json(404, { error: "unknown keyring" });
	const s = stub(env, id);
	const op = rest.slice(1).join("/");
	let out: Result;
	if (op === "" && m === "DELETE") out = await s.remove();
	else if (op === "links" && m === "POST") out = await s.link(await request.text());
	else if (op === "services" && m === "GET") out = await s.services();
	else if (rest[1] === "services" && rest.length === 3 && m === "PUT") out = await s.putService(rest[2], await request.text());
	else if (rest[1] === "keys" && rest.length === 3 && m === "DELETE") out = await s.deleteKey(rest[2]);
	else if (op === "role-token" && m === "POST") out = await s.rotateRoleToken();
	else return json(404, { error: "not found" });
	if ("body" in out) return json(out.status ?? 200, out.body);
	return json(out.status, { error: out.error });
}

type Result = { status?: number; body: unknown } | { status: number; error: string };

/** What the container's admin and consent APIs answer (fields used here). */
interface Reply {
	error?: string;
	token?: string;
	version?: number;
	state?: string;
	url?: string;
	expires_at?: string;
	unlocked?: boolean;
	keys?: string[];
	services?: Record<string, { key: string }>;
	failing?: Record<string, string>;
	roles?: Record<string, { access?: Record<string, unknown>; expires?: string }>;
}

// ---------- Durable Object ----------

/** Fixed for the life of a keyring; written once by create(). */
interface Identity {
	id: string;
	label: string;
	salt: string; // base64, 32 bytes
	adminToken: string; // container admin API
	consentToken: string; // container consent API
	created: string;
}

/** The sealed state and its version (#49). */
interface Sealed {
	state: string;
	version: number;
}

// Storage keys. Each field has its own key, so writers of different fields
// never overwrite each other with a stale copy.
const K_ID = "identity";
const K_SEALED = "sealed";
const K_USAGE = "usage";
const K_OPEN_UNTIL = "openUntil";
const K_SECRETS = "clientSecretsHash";

class Deleted extends Error {}

export class KeyringInstance extends DurableObject<Env> {
	/** The one start in progress or done; null when the container is stopped. */
	private ready: Promise<void> | null = null;
	/** Set synchronously when a delete begins; nothing restarts or writes after it. */
	private deleted = false;
	private inFlight = 0;
	private lastUsed = 0;

	private async identity(): Promise<Identity | undefined> {
		if (this.deleted) return undefined;
		return this.ctx.storage.get<Identity>(K_ID);
	}

	/** Writes one field unless the keyring is being deleted. */
	private async put(key: string, value: unknown): Promise<void> {
		if (this.deleted) throw new Deleted();
		await this.ctx.storage.put(key, value);
	}

	private async dataKey(m: Identity): Promise<string> {
		const master = await crypto.subtle.importKey("raw", unb64(this.env.MASTER_KEY), "HKDF", false, ["deriveBits"]);
		const bits = await crypto.subtle.deriveBits(
			{ name: "HKDF", hash: "SHA-256", salt: unb64(m.salt), info: enc.encode("keyring-instance-v1:" + m.id) },
			master,
			256,
		);
		return b64(bits);
	}

	private port(n: number): Fetcher {
		const c = this.ctx.container;
		if (!c) throw new Error("no container bound to this Durable Object");
		return c.getTcpPort(n);
	}

	/** Calls the container's admin API. */
	private async adminCall(m: Identity, method: string, path: string, body?: unknown, timeoutMs = 30_000): Promise<Response> {
		return this.port(PORT_ADMIN).fetch("http://keyring" + path, {
			method,
			headers: { authorization: "Bearer " + m.adminToken, "content-type": "application/json" },
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(timeoutMs),
		});
	}

	private async adminJSON(m: Identity, method: string, path: string, body?: unknown): Promise<Reply> {
		const r = await this.adminCall(m, method, path, body);
		const out = await reply(r);
		if (!r.ok) throw new KeyringError(r.status, out.error ?? `keyring answered ${r.status}`);
		return out;
	}

	/** Starts the container if needed and waits until it holds this keyring's state. */
	private async start(m: Identity): Promise<void> {
		const c = this.ctx.container!;
		const adminHash = await sha256Hex(m.adminToken);
		if (this.deleted) throw new Deleted();
		if (!c.running) {
			c.start({
				enableInternet: true,
				entrypoint: [
					"/usr/local/bin/keyring", "instance", "--container",
					"--admin-listen", `0.0.0.0:${PORT_ADMIN}`,
					"--admin-token-sha256", adminHash,
				],
			});
			const mine = this.ready;
			c.monitor()
				.catch((e) => console.error("keyring container stopped:", String(e)))
				.finally(() => {
					// Only the start this monitor belongs to is forgotten.
					if (this.ready === mine) this.ready = null;
				});
		}
		for (let i = 0; ; i++) {
			if (this.deleted) throw new Deleted();
			try {
				const r = await this.adminCall(m, "GET", "/status", undefined, 1000);
				if (r.ok) {
					const s = await reply(r);
					const sealed = await this.ctx.storage.get<Sealed>(K_SEALED);
					if (this.deleted) throw new Deleted();
					if (!s.unlocked && sealed) {
						const usage = await this.ctx.storage.get(K_USAGE);
						await this.adminJSON(m, "POST", "/unlock", { data_key: await this.dataKey(m), state: sealed.state, usage });
					}
					break;
				}
			} catch (e) {
				if (e instanceof Deleted || e instanceof KeyringError) throw e;
				// not listening yet
			}
			if (i >= 60) throw new KeyringError(503, "the keyring container did not start");
			await scheduler.wait(250);
		}
		// A new keyring gets them from create(), once it exists.
		if (await this.ctx.storage.get(K_SEALED)) await this.pushClientSecrets(m);
		await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
	}

	/** Makes sure the container runs and holds this keyring's state. One start at a time. */
	private running(m: Identity): Promise<void> {
		if (this.deleted) return Promise.reject(new Deleted());
		this.lastUsed = Date.now();
		if (this.ready) return this.ready;
		const p: Promise<void> = this.start(m).catch((e) => {
			if (this.ready === p) this.ready = null;
			throw e;
		});
		this.ready = p;
		return p;
	}

	/** Saves the container's sealed state if it is newer than the one kept (#49). */
	private async sync(m: Identity): Promise<void> {
		const s = await this.adminJSON(m, "GET", "/state");
		if (s.state === undefined || s.version === undefined) return;
		const cur = await this.ctx.storage.get<Sealed>(K_SEALED);
		if (!cur || s.version > cur.version) await this.put(K_SEALED, { state: s.state, version: s.version } satisfies Sealed);
	}

	private async pushClientSecrets(m: Identity): Promise<void> {
		const raw = this.env.OAUTH_CLIENT_SECRETS ?? "";
		const h = await sha256Hex(raw);
		if (h === (await this.ctx.storage.get<string>(K_SECRETS))) return;
		const secrets = raw ? (JSON.parse(raw) as Record<string, string>) : {};
		for (const [name, value] of Object.entries(secrets)) {
			await this.adminJSON(m, "PUT", `/keys/${name}`, { value });
		}
		await this.sync(m);
		await this.put(K_SECRETS, h);
	}

	// ----- RPC from the Worker's admin routes -----

	async create(id: string, label: string): Promise<{ role_token: string } | { status: number; error: string }> {
		if (this.deleted || (await this.ctx.storage.get(K_ID))) return { status: 409, error: "keyring exists" };
		// A JSON var in wrangler.jsonc arrives as an object; one passed with
		// `wrangler deploy --var` arrives as a string.
		const raw = this.env.SERVICES_TEMPLATE;
		const template = (typeof raw === "string" ? JSON.parse(raw) : raw) as Template;
		if (!template?.services || !template?.access) return { status: 500, error: "SERVICES_TEMPLATE needs services and access" };
		const m: Identity = {
			id, label,
			salt: b64(crypto.getRandomValues(new Uint8Array(32))),
			adminToken: randomToken(),
			consentToken: randomToken(),
			created: new Date().toISOString(),
		};
		await this.put(K_ID, m);
		try {
			await this.running(m);
			await this.adminJSON(m, "POST", "/create", { id, data_key: await this.dataKey(m), listen: `0.0.0.0:${PORT_PROXY}` });
			await this.adminJSON(m, "PUT", "/consent", {
				listen: `0.0.0.0:${PORT_PAGES}`,
				public_url: `${this.env.PUBLIC_BASE}/connect`,
				api_listen: `0.0.0.0:${PORT_CONSENT_API}`,
				api_token_sha256: await sha256Hex(m.consentToken),
			});
			for (const [name, svc] of Object.entries(template.services)) {
				await this.adminJSON(m, "PUT", `/services/${name}`, svc);
			}
			const role = await this.adminJSON(m, "PUT", `/roles/${ROLE}`, { access: template.access });
			await this.pushClientSecrets(m);
			await this.sync(m);
			if (!role.token) throw new KeyringError(502, "the keyring returned no role token");
			return { role_token: role.token };
		} catch (e) {
			// A half-made keyring is removed, not left behind.
			await this.wipe();
			return failure(e);
		}
	}

	async link(body: string): Promise<Result> {
		return this.withInstance(async (m) => {
			const r = await this.port(PORT_CONSENT_API).fetch("http://keyring/links", {
				method: "POST",
				headers: { authorization: "Bearer " + m.consentToken, "content-type": "application/json" },
				body,
			});
			const out = await reply(r);
			if (!r.ok) return { status: r.status, error: out.error ?? "link refused" };
			// The keyring's link is <PUBLIC_BASE>/connect/c/<link>; the person
			// opens it under this keyring's path.
			const prefix = `${this.env.PUBLIC_BASE}/connect/c/`;
			if (typeof out.url !== "string" || !out.url.startsWith(prefix)) return { status: 502, error: "unexpected link" };
			out.url = `${this.env.PUBLIC_BASE}/connect/${m.id}/c/${out.url.slice(prefix.length)}`;
			const until = Date.parse(out.expires_at ?? "") + SIGN_IN_MS;
			if (Number.isNaN(until)) return { status: 502, error: "unexpected link" };
			// Only this method writes the field, and nothing but storage is
			// awaited between the read and the write.
			const cur = (await this.ctx.storage.get<number>(K_OPEN_UNTIL)) ?? 0;
			await this.put(K_OPEN_UNTIL, Math.max(cur, until));
			return { status: 201, body: out };
		});
	}

	async services(): Promise<Result> {
		return this.withInstance(async (m) => {
			const s = await this.adminJSON(m, "GET", "/status");
			const keys = new Set<string>(s.keys ?? []);
			const list = Object.entries(s.services ?? {})
				.map(([name, svc]) => ({ name, connected: keys.has(svc.key), failing: s.failing?.[name] ?? null }))
				.sort((a, b) => a.name.localeCompare(b.name));
			return { body: { services: list } };
		});
	}

	async putService(name: string, body: string): Promise<Result> {
		return this.withInstance(async (m) => {
			const req = JSON.parse(body) as { service: unknown; access?: unknown };
			await this.adminJSON(m, "PUT", `/services/${encodeURIComponent(name)}`, req.service);
			if (req.access !== undefined) {
				const s = await this.adminJSON(m, "GET", "/status");
				const access = { ...(s.roles?.[ROLE]?.access ?? {}), [name]: req.access };
				await this.adminJSON(m, "PUT", `/roles/${ROLE}`, { access, expires: s.roles?.[ROLE]?.expires });
			}
			await this.sync(m);
			return { body: { version: (await this.ctx.storage.get<Sealed>(K_SEALED))?.version } };
		});
	}

	async deleteKey(service: string): Promise<Result> {
		return this.withInstance(async (m) => {
			const r = await this.port(PORT_CONSENT_API).fetch(`http://keyring/keys/${encodeURIComponent(service)}`, {
				method: "DELETE",
				headers: { authorization: "Bearer " + m.consentToken },
			});
			const out = await reply(r);
			await this.sync(m);
			if (!r.ok) return { status: r.status, error: out.error ?? "delete refused" };
			return { body: out };
		});
	}

	async rotateRoleToken(): Promise<Result> {
		return this.withInstance(async (m) => {
			const out = await this.adminJSON(m, "POST", `/roles/${ROLE}/token`);
			await this.sync(m);
			return { body: { role_token: out.token } };
		});
	}

	/** Deletes the keyring. Safe to repeat: an unknown keyring is already gone. */
	async remove(): Promise<Result> {
		await this.wipe();
		return { body: { deleted: true } };
	}

	private async wipe(): Promise<void> {
		// First, before any await: from here on nothing starts the container
		// or writes storage, whatever it read before.
		this.deleted = true;
		const m = await this.ctx.storage.get<Identity>(K_ID);
		const c = this.ctx.container;
		if (m && c?.running) await this.adminCall(m, "DELETE", "/instance").catch(() => {});
		// Also when it does not report running yet: a start may be under way.
		await c?.destroy().catch(() => {});
		this.ready = null;
		await this.ctx.storage.deleteAlarm();
		// The salt goes with the rest: no copy of the state can be opened again.
		await this.ctx.storage.deleteAll();
		// A start that slipped past its check before the flag stops here.
		await c?.destroy().catch(() => {});
	}

	private async withInstance(fn: (m: Identity) => Promise<Result>): Promise<Result> {
		const m = await this.identity();
		if (!m) return { status: 404, error: "unknown keyring" };
		this.inFlight++;
		try {
			await this.running(m);
			return await fn(m);
		} catch (e) {
			return failure(e);
		} finally {
			this.inFlight--;
			this.lastUsed = Date.now();
		}
	}

	// ----- HTTP from the Worker's proxy and consent routes -----

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const m = await this.identity();
		if (url.pathname.startsWith("/_proxy/")) {
			if (!m) return json(404, { error: "unknown keyring" });
			this.inFlight++;
			try {
				await this.running(m);
				const path = "/" + url.pathname.slice("/_proxy/".length) + url.search;
				const headers = new Headers(request.headers);
				headers.delete(CALLER_HEADER);
				return await this.port(PORT_PROXY).fetch("http://keyring" + path, {
					method: request.method, headers, body: request.body, redirect: "manual",
				});
			} catch (e) {
				const f = failure(e);
				return json(f.status, { error: f.error });
			} finally {
				this.inFlight--;
				this.lastUsed = Date.now();
			}
		}
		if (url.pathname.startsWith("/_pages/")) {
			// Links live in the container's memory: a stopped container has
			// no open link, and a stranger cannot wake it.
			const openUntil = (await this.ctx.storage.get<number>(K_OPEN_UNTIL)) ?? 0;
			if (!m || !this.ctx.container?.running || openUntil < Date.now()) {
				return page(410, "This link has expired or was already used. Ask for a new one.");
			}
			this.inFlight++;
			try {
				await this.running(m);
				const path = "/" + url.pathname.slice("/_pages/".length) + url.search;
				const resp = await this.port(PORT_PAGES).fetch("http://keyring" + path, {
					method: request.method, headers: request.headers, body: request.body, redirect: "manual",
				});
				// A link or callback may have stored a key.
				await this.sync(m).catch(() => {});
				const out = new Response(resp.body, resp);
				if (resp.status === 303 && path.startsWith("/connect/c/")) {
					// Off to the provider: the shared callback URL needs to find
					// this keyring again. The keyring still checks its own state
					// and browser cookie.
					out.headers.append("set-cookie", `${INSTANCE_COOKIE}=${m.id}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
				}
				return out;
			} catch {
				return page(410, "This link has expired or was already used. Ask for a new one.");
			} finally {
				this.inFlight--;
			}
		}
		return json(404, { error: "not found" });
	}

	/** Saves daily counts while running; stops an idle container. */
	async alarm(): Promise<void> {
		const m = await this.identity();
		const c = this.ctx.container;
		if (!m || !c?.running) return;
		try {
			await this.put(K_USAGE, await this.adminJSON(m, "GET", "/usage"));
		} catch (e) {
			if (e instanceof Deleted) return;
			// next tick
		}
		const openUntil = (await this.ctx.storage.get<number>(K_OPEN_UNTIL)) ?? 0;
		const idle = this.inFlight === 0 && Date.now() - this.lastUsed > IDLE_MS && openUntil < Date.now();
		if (idle) {
			await this.sync(m).catch(() => {});
			c.signal(15);
			this.ready = null;
			return;
		}
		if (!this.deleted) await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
	}
}

class KeyringError extends Error {
	constructor(readonly status: number, message: string) {
		super(message);
	}
}

/** The JSON body of a keyring reply; {} if it is not JSON. */
async function reply(r: Response): Promise<Reply> {
	const body: unknown = await r.json().catch(() => ({}));
	return body !== null && typeof body === "object" ? (body as Reply) : {};
}

function failure(e: unknown): { status: number; error: string } {
	if (e instanceof KeyringError) return { status: e.status, error: e.message };
	return { status: 502, error: "keyring unavailable" };
}
