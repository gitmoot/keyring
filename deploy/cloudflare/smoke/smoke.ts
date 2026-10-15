// Local check of src/index.ts (Worker + KeyringInstance Durable Object)
// against the real keyring binary, without Cloudflare: `cloudflare:workers`
// and the container runtime are replaced by small fakes, and the "container"
// is a `keyring instance --container` process on loopback ports.
//
//   go build -o /tmp/keyring ./cmd/keyring
//   KEYRING_BIN=/tmp/keyring bun deploy/cloudflare/smoke/smoke.ts
//
// Exits non-zero on the first unexpected answer.
import { plugin, serve, spawn } from "bun";
import type { Subprocess } from "bun";

plugin({
	name: "cloudflare-workers-fake",
	setup(build) {
		build.module("cloudflare:workers", () => ({
			loader: "object",
			exports: {
				DurableObject: class {
					ctx: unknown;
					env: unknown;
					constructor(ctx: unknown, env: unknown) {
						this.ctx = ctx;
						this.env = env;
					}
				},
			},
		}));
	},
});
Object.assign(globalThis, { scheduler: { wait: (ms: number) => Bun.sleep(ms) } });
Object.assign(crypto.subtle, { timingSafeEqual: (a: ArrayBuffer, b: ArrayBuffer) => Buffer.from(a).equals(Buffer.from(b)) });

// Imported after the fake module is registered, so not a static import.
const mod = await import("../src/index.ts");

const BIN = process.env.KEYRING_BIN;
if (!BIN) throw new Error("set KEYRING_BIN to a built keyring binary");

// The API every keyring calls: records what it got.
const seen: { path: string; auth: string; caller: string }[] = [];
const api = serve({
	port: 0,
	hostname: "127.0.0.1",
	fetch(req) {
		seen.push({ path: new URL(req.url).pathname, auth: req.headers.get("authorization") ?? "", caller: req.headers.get("x-keyring-caller") ?? "" });
		return new Response("ok");
	},
});

let nextPort = 19100 + Math.floor(Math.random() * 500) * 20;
/** A base whose four container ports (8080-8082, 8090 mapped) are free now. */
function freeBase(): number {
	for (;;) {
		const base = nextPort;
		nextPort += 20;
		if (nextPort > 60000) nextPort = 19100;
		const free = [0, 1, 2, 10].every((d) => {
			try {
				const l = Bun.listen({ hostname: "127.0.0.1", port: base + d, socket: { data() {} } });
				l.stop(true);
				return true;
			} catch {
				return false;
			}
		});
		if (free) return base;
	}
}
let starts = 0;
/** A container whose ports P map to host ports base+P-8080, kept across restarts. */
class FakeContainer {
	proc: Subprocess | null = null;
	pending: Timer | null = null;
	base = 0;
	get running() {
		return this.proc !== null && this.proc.exitCode === null;
	}
	map(s: string): string {
		return s.replace(/0\.0\.0\.0:(\d+)/g, (_, p: string) => `127.0.0.1:${this.base + Number(p) - 8080}`);
	}
	start(opts: { entrypoint: string[] }) {
		if (!this.base) this.base = freeBase();
		starts++;
		// `running` turning true right away is not documented, so here it
		// turns true a little later.
		this.pending = setTimeout(() => {
			this.pending = null;
			this.proc = spawn([BIN!, ...opts.entrypoint.slice(1).map((a) => this.map(a))], { stdout: "ignore", stderr: "ignore" });
		}, 20);
	}
	async monitor() {
		await this.proc?.exited;
	}
	async destroy() {
		// Like the runtime's destroy(), this also ends a start under way.
		if (this.pending) clearTimeout(this.pending);
		this.pending = null;
		this.proc?.kill(9);
		await this.proc?.exited;
		this.proc = null;
	}
	inactivityMs = 0;
	async setInactivityTimeout(ms: number) {
		this.inactivityMs = ms;
	}
	signal(n: number) {
		this.proc?.kill(n);
	}
	getTcpPort(p: number) {
		return {
			fetch: (u: string, init?: RequestInit) =>
				fetch(u.replace("http://keyring", `http://127.0.0.1:${this.base + p - 8080}`), {
					...init,
					body: typeof init?.body === "string" ? this.map(init.body) : init?.body,
				}),
		};
	}
}

class Storage {
	m = new Map<string, unknown>();
	async get<T>(k: string) {
		return structuredClone(this.m.get(k)) as T | undefined;
	}
	async put(k: string, v: unknown) {
		this.m.set(k, structuredClone(v));
	}
	async deleteAll() {
		this.m.clear();
	}
	async setAlarm() {}
	async deleteAlarm() {}
}

const objects = new Map<string, InstanceType<typeof mod.KeyringInstance>>();
const storages = new Map<string, Storage>();
const containers = new Map<string, FakeContainer>();
const env = {
	PUBLIC_BASE: "https://keyring.test",
	MASTER_KEY: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64"),
	CALLER_SECRET: "caller-secret",
	ADMIN_TOKEN: "admin-token",
	OAUTH_CLIENT_SECRETS: JSON.stringify({ GOOGLE_CLIENT_SECRET: "client-secret-value" }),
	// Passed as a string when SMOKE_TEMPLATE_AS_STRING is set, as `wrangler deploy --var` does.
	SERVICES_TEMPLATE: ((t: object) => (process.env.SMOKE_TEMPLATE_AS_STRING ? JSON.stringify(t) : t))({
		services: {
			echo: { base: `http://127.0.0.1:${api.port}`, key: "ECHO_KEY", auth: "bearer" },
			gmail: {
				base: "https://gmail.googleapis.com", key: "GMAIL_REFRESH", auth: "oauth2",
				oauth2: {
					token_url: "https://oauth2.example.com/token", client_id: "cid", client_secret_key: "GOOGLE_CLIENT_SECRET",
					auth_url: "https://accounts.example.com/auth", scopes: ["https://mail.google.com/"],
				},
			},
		},
		access: { echo: { paths: ["/"], daily_requests: 3 }, gmail: { paths: ["/"] } },
	}),
	KEYRING: {
		idFromName: (n: string) => n,
		get: (name: string) => {
			let o = objects.get(name);
			if (!o) {
				if (!storages.has(name)) storages.set(name, new Storage());
				if (!containers.has(name)) containers.set(name, new FakeContainer());
				o = new mod.KeyringInstance(
					{ storage: storages.get(name), container: containers.get(name), blockConcurrencyWhile: (f: () => Promise<unknown>) => f() } as never,
					env as never,
				);
				objects.set(name, o);
			}
			return o;
		},
	},
};

const call = (method: string, path: string, headers: Record<string, string> = {}, body?: string) =>
	mod.default.fetch(new Request("https://keyring.test" + path, { method, headers, body, redirect: "manual" }), env as never);

let failed = false;
function expect(what: string, got: unknown, want: unknown) {
	const ok = JSON.stringify(got) === JSON.stringify(want);
	console.log(`${ok ? "ok  " : "FAIL"} ${what}: ${JSON.stringify(got)}${ok ? "" : ` (want ${JSON.stringify(want)})`}`);
	if (!ok) failed = true;
}

const ADMIN = { "x-keyring-caller": "caller-secret", authorization: "Bearer admin-token" };
const FORM = { origin: "https://keyring.test", "content-type": "application/x-www-form-urlencoded" };
try {
	expect("admin with a wrong caller proof", (await call("POST", "/admin/instances", { ...ADMIN, "x-keyring-caller": "x" }, "{}")).status, 401);
	expect("admin with a wrong admin token", (await call("POST", "/admin/instances", { ...ADMIN, authorization: "Bearer x" }, "{}")).status, 401);
	let r = await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "Alice" }));
	const created = (await r.json()) as { keyring_id: string; keyring_base: string; role_token: string };
	expect("create", [r.status, created.keyring_base?.startsWith("https://keyring.test/p/"), typeof created.role_token], [201, true, "string"]);
	const id = created.keyring_id;
	const P = { "x-keyring-caller": "caller-secret", "x-keyring-token": created.role_token };

	r = await call("GET", `/admin/instances/${id}/services`, ADMIN);
	expect("services", await r.json(), { services: [{ name: "echo", connected: false, failing: null }, { name: "gmail", connected: false, failing: null }] });
	expect("call before connect", (await call("GET", `/p/${id}/echo/x`, P)).status, 503);
	expect("call without caller proof", (await call("GET", `/p/${id}/echo/x`, { "x-keyring-token": created.role_token })).status, 401);

	r = await call("POST", `/admin/instances/${id}/links`, ADMIN, JSON.stringify({ service: "echo" }));
	const link = new URL(((await r.json()) as { url: string }).url).pathname;
	expect("link", [r.status, link.startsWith(`/connect/${id}/c/`)], [201, true]);
	expect("open link", (await call("GET", link)).status, 200);
	expect("post value", (await call("POST", link, FORM, "value=echo-secret-123")).status, 200);
	expect("reuse link", (await call("GET", link)).status, 410);
	const codes = [];
	for (let i = 1; i <= 4; i++) codes.push((await call("GET", `/p/${id}/echo/x${i}`, P)).status);
	expect("calls with daily limit 3", codes, [200, 200, 200, 429]);
	expect("container keeps running between alarms (inactivity timeout set)", containers.get(id)!.inactivityMs, 15 * 60 * 1000);
	expect("upstream got the key, never the caller proof", seen.map((s) => [s.auth, s.caller]), [
		["Bearer echo-secret-123", ""], ["Bearer echo-secret-123", ""], ["Bearer echo-secret-123", ""],
	]);
	const stored = JSON.stringify([...storages.get(id)!.m]);
	expect("Durable Object keeps only sealed state", [storages.get(id)!.m.has("sealed"), stored.includes("echo-secret-123")], [true, false]);

	await objects.get(id)!.alarm();
	expect("alarm keeps usage", storages.get(id)!.m.get("usage"), {
		day: new Date().toISOString().slice(0, 10), counts: [{ role: "router", service: "echo", count: 3 }],
	});
	// The container sleeps: its process and the object's memory are gone.
	await containers.get(id)!.destroy();
	objects.delete(id);
	expect("after a restart, the daily limit holds", [(await call("GET", `/p/${id}/echo/x5`, P)).status, starts], [429, 2]);

	// Concurrent calls on a stopped container start it once (review P3).
	await containers.get(id)!.destroy();
	objects.get(id)!["ready" as never] = null as never;
	const before = starts;
	const both = await Promise.all([call("GET", `/p/${id}/echo/z1`, P), call("GET", `/p/${id}/echo/z2`, P)]);
	expect("two calls on a stopped container: one start", [both.map((x) => x.status), starts - before], [[429, 429], 1]);

	r = await call("POST", `/admin/instances/${id}/role-token`, ADMIN);
	const token2 = ((await r.json()) as { role_token: string }).role_token;
	expect("old role token after rotation", (await call("GET", `/p/${id}/echo/y`, P)).status, 401);
	expect("gmail not connected", (await call("GET", `/p/${id}/gmail/x`, { ...P, "x-keyring-token": token2 })).status, 503);

	r = await call("POST", `/admin/instances/${id}/links`, ADMIN, JSON.stringify({ service: "gmail" }));
	const glink = new URL(((await r.json()) as { url: string }).url).pathname;
	r = await call("POST", glink, FORM, "");
	const loc = new URL(r.headers.get("location") ?? "about:blank");
	expect("gmail sign-in", [r.status, loc.origin, loc.searchParams.get("redirect_uri"), r.headers.getSetCookie().map((c) => c.split("=")[0]).sort()], [
		303, "https://accounts.example.com", "https://keyring.test/connect/callback", ["__Host-keyring-consent", "__Host-keyring-instance"],
	]);
	// An open link cannot wake a stopped container: strangers can reach /connect.
	r = await call("POST", `/admin/instances/${id}/links`, ADMIN, JSON.stringify({ service: "echo" }));
	const sleepy = new URL(((await r.json()) as { url: string }).url).pathname;
	await containers.get(id)!.destroy();
	objects.get(id)!["ready" as never] = null as never;
	const startsBefore = starts;
	r = await call("GET", sleepy);
	expect("link page on a stopped container", [r.status, starts - startsBefore, containers.get(id)!.running], [410, 0, false]);

	r = await call("GET", "/connect/callback?state=x&code=y");
	expect("callback without the instance cookie", r.status, 400);

	expect("delete key", await (await call("DELETE", `/admin/instances/${id}/keys/echo`, ADMIN)).json(), { deleted: true, key: "ECHO_KEY" });
	expect("delete keyring", (await call("DELETE", `/admin/instances/${id}`, ADMIN)).status, 200);
	expect("storage and container after delete", [storages.get(id)!.m.size, containers.get(id)!.running], [0, false]);
	expect("delete again", (await call("DELETE", `/admin/instances/${id}`, ADMIN)).status, 200);
	expect("call after delete", (await call("GET", `/p/${id}/echo/x`, { ...P, "x-keyring-token": token2 })).status, 404);

	// A delete racing calls that already started (review of b6a41be, P1):
	// the container must not come back and storage must stay empty.
	for (const racer of ["proxy", "page", "admin"]) {
		for (const deleteFirst of [true, false]) {
			r = await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "race" }));
			if (r.status !== 201) throw new Error(`race setup: create ${r.status} ${await r.text()}`);
			const k = (await r.json()) as { keyring_id: string; role_token: string };
			const RP = { "x-keyring-caller": "caller-secret", "x-keyring-token": k.role_token };
			r = await call("POST", `/admin/instances/${k.keyring_id}/links`, ADMIN, JSON.stringify({ service: "echo" }));
			const rl = new URL(((await r.json()) as { url: string }).url).pathname;
			if (racer !== "page") {
				// Stopped, as after idle, so the racer has to start it. (A link
				// page never starts a stopped container.)
				await containers.get(k.keyring_id)!.destroy();
				objects.get(k.keyring_id)!["ready" as never] = null as never;
			}
			const racing = () =>
				racer === "proxy" ? call("GET", `/p/${k.keyring_id}/echo/race`, RP)
				: racer === "page" ? call("POST", rl, FORM, "value=late")
				: call("POST", `/admin/instances/${k.keyring_id}/role-token`, ADMIN);
			const del = () => call("DELETE", `/admin/instances/${k.keyring_id}`, ADMIN);
			// The racing call may land before the delete (any status); what
			// must hold is that nothing is left running or stored afterwards.
			await Promise.all(deleteFirst ? [del(), racing()] : [racing(), del()]);
			await Bun.sleep(300);
			expect(`delete ${deleteFirst ? "before" : "after"} a racing ${racer} call`, [containers.get(k.keyring_id)!.running, storages.get(k.keyring_id)!.m.size], [false, 0]);
		}
	}

	// Writers of different fields never undo each other (review P2).
	r = await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "fields" }));
	const kf = ((await r.json()) as { keyring_id: string }).keyring_id;
	await Promise.all([
		call("POST", `/admin/instances/${kf}/links`, ADMIN, JSON.stringify({ service: "echo" })),
		objects.get(kf)!.alarm(),
	]);
	expect("link keep-alive survives a concurrent alarm", [typeof storages.get(kf)!.m.get("openUntil"), typeof storages.get(kf)!.m.get("usage")], ["number", "object"]);
	await call("DELETE", `/admin/instances/${kf}`, ADMIN);
} finally {
	for (const c of containers.values()) await c.destroy();
	api.stop(true);
}
process.exit(failed ? 1 : 0);
