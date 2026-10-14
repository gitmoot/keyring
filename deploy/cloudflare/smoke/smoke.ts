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
let starts = 0;
/** A container whose ports P map to host ports base+P-8080, kept across restarts. */
class FakeContainer {
	proc: Subprocess | null = null;
	base = 0;
	get running() {
		return this.proc !== null && this.proc.exitCode === null;
	}
	map(s: string): string {
		return s.replace(/0\.0\.0\.0:(\d+)/g, (_, p: string) => `127.0.0.1:${this.base + Number(p) - 8080}`);
	}
	start(opts: { entrypoint: string[] }) {
		if (!this.base) {
			this.base = nextPort;
			nextPort += 20;
		}
		this.proc = spawn([BIN!, ...opts.entrypoint.slice(1).map((a) => this.map(a))], { stdout: "ignore", stderr: "ignore" });
		starts++;
	}
	async monitor() {
		await this.proc?.exited;
	}
	async destroy() {
		this.proc?.kill(9);
		await this.proc?.exited;
		this.proc = null;
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
	// The object stores one record ("meta"); kept as a plain object here.
	m = new Map<string, Record<string, unknown>>();
	async get<T>(k: string) {
		return structuredClone(this.m.get(k)) as T | undefined;
	}
	async put(k: string, v: Record<string, unknown>) {
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
	SERVICES_TEMPLATE: {
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
	},
	KEYRING: {
		idFromName: (n: string) => n,
		get: (name: string) => {
			let o = objects.get(name);
			if (!o) {
				if (!storages.has(name)) storages.set(name, new Storage());
				if (!containers.has(name)) containers.set(name, new FakeContainer());
				o = new mod.KeyringInstance({ storage: storages.get(name), container: containers.get(name) } as never, env as never);
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
	expect("upstream got the key, never the caller proof", seen.map((s) => [s.auth, s.caller]), [
		["Bearer echo-secret-123", ""], ["Bearer echo-secret-123", ""], ["Bearer echo-secret-123", ""],
	]);
	const meta = storages.get(id)!.m.get("meta") ?? {};
	expect("Durable Object keeps only sealed state", [typeof meta.state, JSON.stringify(meta).includes("echo-secret-123")], ["string", false]);

	await objects.get(id)!.alarm();
	expect("alarm keeps usage", storages.get(id)!.m.get("meta")?.usage, {
		day: new Date().toISOString().slice(0, 10), counts: [{ role: "router", service: "echo", count: 3 }],
	});
	// The container sleeps: its process and the object's memory are gone.
	await containers.get(id)!.destroy();
	objects.delete(id);
	expect("after a restart, the daily limit holds", [(await call("GET", `/p/${id}/echo/x5`, P)).status, starts], [429, 2]);

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
	r = await call("GET", "/connect/callback?state=x&code=y");
	expect("callback without the instance cookie", r.status, 400);

	expect("delete key", await (await call("DELETE", `/admin/instances/${id}/keys/echo`, ADMIN)).json(), { deleted: true, key: "ECHO_KEY" });
	expect("delete keyring", (await call("DELETE", `/admin/instances/${id}`, ADMIN)).status, 200);
	expect("storage and container after delete", [storages.get(id)!.m.size, containers.get(id)!.running], [0, false]);
	expect("delete again", (await call("DELETE", `/admin/instances/${id}`, ADMIN)).status, 200);
	expect("call after delete", (await call("GET", `/p/${id}/echo/x`, { ...P, "x-keyring-token": token2 })).status, 404);
} finally {
	for (const c of containers.values()) await c.destroy();
	api.stop(true);
}
process.exit(failed ? 1 : 0);
