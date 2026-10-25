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
	/**
	 * https origin of this Worker, e.g. https://keyring.example.com. It may
	 * change: each keyring gets the new consent URL on its next start.
	 */
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
	/** Optional additive JSON map; shared clients override globals but never per-instance entries. */
	OAUTH_CLIENT_SECRETS_SHARED?: string;
	/** Secret (optional): JSON {"keyring_id": {"KEY_NAME": "value"}}; selected values override globals only in that instance. */
	OAUTH_CLIENT_SECRETS_BY_INSTANCE?: string;
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
/**
 * How long Cloudflare keeps the container after the Durable Object goes
 * inactive. Without it the platform stops the container soon after the last
 * request, before the keyring's own idle stop and while links may be open
 * (seen live: stopped about 6 minutes after the last call). The alarm, every
 * minute, keeps the object active; the keyring decides when to stop.
 */
const INACTIVITY_MS = 15 * 60 * 1000;
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
			if (!ID.test(id ?? "") || !["c", "g"].includes(parts[3] ?? "")) return page(404, "Not found.");
			// A link issued under an earlier PUBLIC_BASE: its form must be posted
			// from PUBLIC_BASE's origin (the keyring checks Origin), so it opens
			// there. A sign-in already started (g/) stays put: its browser cookie
			// is only on the host it started on.
			if (parts[3] === "c" && url.origin !== new URL(env.PUBLIC_BASE).origin) {
				return new Response(null, { status: 303, headers: { location: env.PUBLIC_BASE + url.pathname + url.search, "cache-control": "no-store" } });
			}
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
	else if (op === "google-renewal" && m === "GET") out = await s.googleRenewal();
	else if (op === "google-drive" && m === "POST") out = await s.provisionGoogle(await request.text());
	else if (rest[1] === "services" && rest.length === 3 && m === "PUT") out = await s.putService(rest[2], await request.text());
	else if (rest[1] === "keys" && rest.length === 3 && m === "DELETE") out = await s.deleteKey(rest[2]);
	else if (
		(op === "accounts" && (m === "GET" || m === "POST")) ||
		(op === "accounts/migrate" && m === "POST") ||
		(rest[1] === "accounts" && ID.test(rest[2] ?? "") &&
			((rest.length === 3 && m === "DELETE") ||
				(rest.length === 4 && m === "POST" && ["identity", "links"].includes(rest[3]))))
	) out = await s.accounts(op, m, m === "POST" ? await request.text() : undefined, request.headers.get("X-Keyring-Binding-Generation") ?? "");
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
	services?: Record<string, { key: string; auth?: string; google_account?: string }>;
	google?: { phase: string; busy: boolean; error?: string };
	failing?: Record<string, string>;
	reconnect_required?: Record<string, boolean>;
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
const K_LAST_USED = "lastUsed";
/** The consent public_url last sent to the keyring and saved in its sealed state. */
const K_CONSENT_URL = "consentPublicUrl";
/** lastUsed is written to storage at most this often. */
const LAST_USED_WRITE_MS = 30 * 1000;

class Deleted extends Error {}

export class KeyringInstance extends DurableObject<Env> {

	/** The one start in progress or done; null when the container is stopped. */
	private ready: Promise<void> | null = null;
	/** Set synchronously when a delete begins; nothing restarts or writes after it. */
	private deleted = false;
	private inFlight = 0;
	/**
	 * Last call, kept in storage too: an object evicted between alarms comes
	 * back without its memory, and must neither stop a container just in use
	 * nor count idle time from zero again.
	 */
	private lastUsed = 0;
	private lastUsedStored = 0;
	/** A start() is between c.start() and the end of its wait. */
	private starting = false;
	// Restored only by normal lifecycle work, never by a diagnostic-only wake.
	private inactivityConfigured = false;

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
		this.starting = true;
		try {
			await this.startAndUnlock(m, c);
		} finally {
			this.starting = false;
		}
		// A new keyring gets them from create(), once it exists.
		if (await this.ctx.storage.get(K_SEALED)) {
			await this.pushConsent(m);
			await this.pushClientSecrets(m);
		}
		await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
	}

	private async startAndUnlock(m: Identity, c: Container): Promise<void> {
		const adminHash = await sha256Hex(m.adminToken);
		if (this.deleted) throw new Deleted();
		if (!c.running) {
			console.log(`keyring container starting (${m.id})`);
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
		await c.setInactivityTimeout(INACTIVITY_MS);
		this.inactivityConfigured = true;
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
						console.log(`keyring unlocked from sealed state v${sealed.version} (${m.id})`);
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
	}

	/** Records a call; stores it now and then, never while deleting. */
	private touch(): void {
		const now = Date.now();
		this.lastUsed = now;
		if (now - this.lastUsedStored >= LAST_USED_WRITE_MS && !this.deleted) {
			this.lastUsedStored = now;
			this.ctx.storage.put(K_LAST_USED, now).catch(() => {});
		}
	}

	/** Makes sure the container runs and holds this keyring's state. One start at a time. */
	private running(m: Identity): Promise<void> {
		if (this.deleted) return Promise.reject(new Deleted());
		this.touch();
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

	/** The keyring's consent settings; public_url follows PUBLIC_BASE. */
	private async consentSettings(m: Identity) {
		return {
			listen: `0.0.0.0:${PORT_PAGES}`,
			public_url: `${this.env.PUBLIC_BASE}/connect`,
			api_listen: `0.0.0.0:${PORT_CONSENT_API}`,
			api_token_sha256: await sha256Hex(m.consentToken),
		};
	}

	/**
	 * Sends the consent settings again when PUBLIC_BASE changed since they
	 * were last sent. The keyring builds link, Google page and callback URLs
	 * from its own public_url, kept in its sealed state; publishLink and the
	 * page route expect them under PUBLIC_BASE. Open links and accounts stay.
	 */
	private async pushConsent(m: Identity): Promise<void> {
		const consent = await this.consentSettings(m);
		if (consent.public_url === (await this.ctx.storage.get<string>(K_CONSENT_URL))) return;
		await this.adminJSON(m, "PUT", "/consent", consent);
		await this.sync(m);
		await this.put(K_CONSENT_URL, consent.public_url);
	}

	private async pushClientSecrets(m: Identity): Promise<void> {
		let secrets: Record<string, string>;
		try {
			const global = this.env.OAUTH_CLIENT_SECRETS ? JSON.parse(this.env.OAUTH_CLIENT_SECRETS) : {};
			const shared = this.env.OAUTH_CLIENT_SECRETS_SHARED ? JSON.parse(this.env.OAUTH_CLIENT_SECRETS_SHARED) : {};
			const scoped = JSON.parse(this.env.OAUTH_CLIENT_SECRETS_BY_INSTANCE || "{}");
			secrets = { ...global, ...shared, ...scoped[m.id] };
		} catch {
			// JSON parse errors can quote the input: never expose secret text.
			throw new Error("OAuth client-secret settings must be valid JSON objects");
		}
		const h = await sha256Hex(JSON.stringify(secrets));
		if (h === (await this.ctx.storage.get<string>(K_SECRETS))) return;
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
			const consent = await this.consentSettings(m);
			await this.adminJSON(m, "PUT", "/consent", consent);
			for (const [name, svc] of Object.entries(template.services)) {
				await this.adminJSON(m, "PUT", `/services/${name}`, svc);
			}
			const role = await this.adminJSON(m, "PUT", `/roles/${ROLE}`, { access: template.access });
			if (template.services.drive?.auth === "gcloud-login") {
				await this.adminJSON(m, "POST", "/google-drive", {});
			}
			await this.pushClientSecrets(m);
			await this.sync(m);
			await this.put(K_CONSENT_URL, consent.public_url);
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
			return this.publishLink(m, out);
		});
	}

	private async publishLink(m: Identity, out: Reply): Promise<Result> {
		const prefix = `${this.env.PUBLIC_BASE}/connect/c/`;
		if (typeof out.url !== "string" || !out.url.startsWith(prefix)) return { status: 502, error: "unexpected link" };
		out.url = `${this.env.PUBLIC_BASE}/connect/${m.id}/c/${out.url.slice(prefix.length)}`;
		const until = Date.parse(out.expires_at ?? "") + SIGN_IN_MS;
		if (Number.isNaN(until)) return { status: 502, error: "unexpected link" };
		// Keep the existing consent lifetime and monotonic idle deadline.
		const cur = (await this.ctx.storage.get<number>(K_OPEN_UNTIL)) ?? 0;
		await this.put(K_OPEN_UNTIL, Math.max(cur, until));
		return { status: 201, body: out };
	}

	async accounts(path: string, method: string, body: string | undefined, generation: string): Promise<Result> {
		return this.withInstance(async (m) => {
			const response = await this.port(PORT_ADMIN).fetch("http://keyring/" + path, {
				method,
				headers: {
					authorization: "Bearer " + m.adminToken,
					"content-type": "application/json",
					"X-Keyring-Binding-Generation": generation,
				},
				body,
				signal: AbortSignal.timeout(60_000),
			});
			const out = await reply(response);
			if (!response.ok) return { status: response.status, error: out.error ?? "account_operation_failed" };
			if (path.endsWith("/links")) return this.publishLink(m, out);
			if (method !== "GET") await this.sync(m);
			return { status: response.status, body: out };
		});
	}

	async provisionGoogle(body: string): Promise<Result> {
		return this.withInstance(async (m) => {
			const r = await this.port(PORT_ADMIN).fetch("http://keyring/google-drive", {
				method: "POST",
				headers: { authorization: "Bearer " + m.adminToken, "content-type": "application/json" },
				body,
				signal: AbortSignal.timeout(30_000),
			});
			const out = await reply(r);
			if (!r.ok) return { status: r.status, error: out.error ?? "Google provisioning refused" };
			await this.sync(m);
			return { body: { version: out.version } };
		});
	}

	async services(): Promise<Result> {
		return this.withInstance(async (m) => {
			const s = await this.adminJSON(m, "GET", "/status");
			const keys = new Set<string>(s.keys ?? []);
			const list = Object.entries(s.services ?? {})
				.map(([name, svc]) => {
					const google = svc.google_account === "me" && (svc.auth === "gcloud" || svc.auth === "gcloud-login");
					return { name, connected: google ? s.google?.phase === "connected" : keys.has(svc.key) && !s.reconnect_required?.[name],
						failing: google ? s.google?.error ?? s.failing?.[name] ?? (s.google?.phase === "connected" ? null : "Google connection is not ready") : s.failing?.[name] ?? null };
				})
				.sort((a, b) => a.name.localeCompare(b.name));
			return { body: { services: list } };
		});
	}

	/** Strict observation: no withInstance/running, unlock, import, sync or touch. */
	async googleRenewal(): Promise<Result> {
		const m = await this.identity();
		if (!m || this.deleted) return { status: 404, error: "unknown keyring" };
		const c = this.ctx.container;
		if (this.starting) return { body: { available: false, reason: "starting" } };
		if (!c?.running) return { body: { available: false, reason: "container_not_running" } };
		// Do not pin an idle container. A concurrent shutdown may fail this read.
		try {
			const r = await this.adminCall(m, "GET", "/google-renewal", undefined, 2_000);
			if (!r.ok) return { status: 503, error: "Google renewal diagnostics unavailable" };
			const body = await renewalView(r);
			if (this.deleted) return { status: 404, error: "unknown keyring" };
			return { body };
		} catch {
			return { status: 503, error: "Google renewal diagnostics unavailable" };
		}
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
			this.touch();
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
				const response = await this.port(PORT_PROXY).fetch("http://keyring" + path, {
					method: request.method, headers, body: request.body, redirect: "manual",
				});
				// A Google token refresh can change the encrypted SDK state.
				// Do not acknowledge the proxy result before preserving it.
				await this.sync(m);
				return response;
			} catch (e) {
				const f = failure(e);
				return json(f.status, { error: f.error });
			} finally {
				this.inFlight--;
				this.touch();
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
				await this.sync(m);
				const out = new Response(resp.body, resp);
				const googlePrefix = `${this.env.PUBLIC_BASE}/connect/g/`;
				const location = out.headers.get("location");
				if (resp.status === 303 && location?.startsWith(googlePrefix)) {
					out.headers.set("location", `${this.env.PUBLIC_BASE}/connect/${m.id}/g/${location.slice(googlePrefix.length)}`);
				}
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
		if (!m || !c) return;
		if (!c.running) {
			if (this.starting) {
				// Not up yet; look again next tick.
				if (!this.deleted) await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
				return;
			}
			// Alarms run only while a container is up: this one was stopped
			// by the platform, not by the idle check below.
			console.log(`keyring container found stopped (${m.id})`);
			this.ready = null;
			return;
		}
		try {
			if (!this.inactivityConfigured) {
				await c.setInactivityTimeout(INACTIVITY_MS);
				this.inactivityConfigured = true;
			}
			await this.put(K_USAGE, await this.adminJSON(m, "GET", "/usage"));
		} catch (e) {
			if (e instanceof Deleted) return;
			// next tick
		}
		const openUntil = (await this.ctx.storage.get<number>(K_OPEN_UNTIL)) ?? 0;
		let stored = await this.ctx.storage.get<number>(K_LAST_USED);
		if (stored === undefined) {
			// No record yet (a keyring from before this was kept): start
			// counting now rather than stop a container that may be in use.
			stored = Date.now();
			await this.put(K_LAST_USED, stored).catch(() => {});
		}
		const last = Math.max(this.lastUsed, stored);
		const idle = this.inFlight === 0 && Date.now() - last > IDLE_MS && openUntil < Date.now();
		if (idle) {
			// Preserve background login/project changes even when its browser
			// vanished. A failed save must never lead to discarding credentials.
			try {
				const status = await this.adminJSON(m, "GET", "/status");
				await this.sync(m);
				if (status.google?.busy) {
					await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
					return;
				}
			} catch {
				if (!this.deleted) await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
				return;
			}
			console.log(`keyring container stopped (idle) (${m.id})`);
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

/** Bound the response and reconstruct only fixed, credential-free fields. */
async function renewalView(response: Response): Promise<unknown> {
	const reader = response.body?.getReader();
	if (!reader) throw new Error("missing diagnostics");
	let text = "";
	let size = 0;
	const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
	try {
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > 16_384) throw new Error("oversized diagnostics");
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
	} finally {
		await reader.cancel().catch(() => {});
	}
	const object = (value: unknown): Record<string, unknown> => {
		if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid diagnostics");
		return value as Record<string, unknown>;
	};
	const choice = (value: unknown, allowed: readonly string[]): string => {
		if (typeof value !== "string" || !allowed.includes(value)) throw new Error("invalid diagnostics");
		return value;
	};
	const integer = (value: unknown, minimum = 0): number => {
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) throw new Error("invalid diagnostics");
		return value;
	};
	const timestamp = (value: unknown): string => {
		if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) ||
			!Number.isFinite(Date.parse(value))) throw new Error("invalid diagnostics");
		return value;
	};
	const data = object(JSON.parse(text));
	if (data.available === false) {
		const reason = choice(data.reason, ["locked", "no_attempt"]);
		return reason === "locked" ? { available: false, reason } :
			{ available: false, reason, process_started_at: timestamp(data.process_started_at) };
	}
	if (data.available !== true) throw new Error("invalid diagnostics");
	const attempt = object(data.attempt);
	const phases = ["configuration", "controller_wait", "sdk_execution", "persistence", "token_validation"] as const;
	const outcomes = ["running", "success", "timeout", "canceled", "error"] as const;
	const process = object(attempt.process);
	if (typeof process.available !== "boolean" || !Array.isArray(attempt.steps) || attempt.steps.length !== phases.length) {
		throw new Error("invalid diagnostics");
	}
	const steps = attempt.steps.map((value, i) => {
		const step = object(value);
		return { phase: choice(step.phase, [phases[i]]), duration_ms: integer(step.duration_ms),
			outcome: choice(step.outcome, [...outcomes, "not_run"]) };
	});
	return {
		available: true, process_started_at: timestamp(data.process_started_at),
		attempt: {
			started_at: timestamp(attempt.started_at),
			...(attempt.completed_at === undefined ? {} : { completed_at: timestamp(attempt.completed_at) }),
			phase: choice(attempt.phase, [...phases, "complete"]), outcome: choice(attempt.outcome, outcomes),
			duration_ms: integer(attempt.duration_ms), steps,
			process: { available: process.available, cpu_time_ms: integer(process.cpu_time_ms),
				exit_code: integer(process.exit_code, -1), signal: integer(process.signal) },
		},
	};
}
