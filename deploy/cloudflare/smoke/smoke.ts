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
	// Like the runtime's monitor(): resolves when the container started by
	// the last start() has exited, including one still starting.
	async monitor() {
		while (this.pending) await Bun.sleep(5);
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
	timeoutWrites = 0;
	diagnosticCalls = 0;
	diagnosticOverride: (() => Response | Promise<Response>) | null = null;
	inactivityMs = 0;
	async setInactivityTimeout(ms: number) {
		this.timeoutWrites++;
		this.inactivityMs = ms;
	}
	signal(n: number) {
		this.proc?.kill(n);
	}
	getTcpPort(p: number) {
		return {
			fetch: (u: string, init?: RequestInit) => {
				if (p === 8090 && new URL(u).pathname === "/google-renewal") {
					this.diagnosticCalls++;
					if (this.diagnosticOverride) return Promise.resolve(this.diagnosticOverride());
				}
				return fetch(u.replace("http://keyring", `http://127.0.0.1:${this.base + p - 8080}`), {
					...init,
					body: typeof init?.body === "string" ? this.map(init.body) : init?.body,
				});
			},
		};
	}
}

class Storage {
	m = new Map<string, unknown>();
	alarm: number | null = null;
	async get<T>(k: string) {
		return structuredClone(this.m.get(k)) as T | undefined;
	}
	writes = 0;
	async put(k: string, v: unknown) {
		this.writes++;
		this.m.set(k, structuredClone(v));
	}
	async deleteAll() {
		this.writes++;
		this.m.clear();
	}
	async setAlarm(when: number) { this.writes++; this.alarm = when; }
	async deleteAlarm() { this.writes++; this.alarm = null; }
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
	OAUTH_CLIENT_SECRETS_BY_INSTANCE: "{}",
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

	expect("provision Drive on an existing instance", (await call("POST", `/admin/instances/${id}/google-drive`, ADMIN, "{}")).status, 200);
	expect("repeat Drive provisioning", (await call("POST", `/admin/instances/${id}/google-drive`, ADMIN, "{}")).status, 200);
	expect("reject caller-selected Google provisioning", (await call("POST", `/admin/instances/${id}/google-drive`, ADMIN, '{"executable":"/tmp/gcloud"}')).status, 400);
	expect("same token authorizes disconnected Drive", (await call("GET", `/p/${id}/google-me-drive/about`, P)).status, 503);
	const driveServices = (await (await call("GET", `/admin/instances/${id}/services`, ADMIN)).json()) as { services: { name: string; connected: boolean; failing: string | null }[] };
	const driveNames = ["drive", "google-me-drive", "google-me-sheets", "google-me-upload"];
	expect("all provisioned Google services start disconnected", driveServices.services.filter(s => driveNames.includes(s.name)).map(s => [s.name, s.connected]), driveNames.map(name => [name, false]));
	expect("Drive status contains no identity or credentials", driveServices.services.filter(s => driveNames.includes(s.name)).every(s => Object.keys(s).sort().join() === "connected,failing,name"), true);

	// A diagnostic-only DO wake must not renew platform idle time or sealed state.
	const dc = containers.get(id)!;
	const ds = storages.get(id)!;
	const unchanged = () => [starts, dc.timeoutWrites, ds.writes, ds.alarm, JSON.stringify([...ds.m])];
	const beforeDiagnostic = unchanged();
	objects.delete(id);
	let diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	const emptyDiagnostic = await diagnostic.json() as { available: boolean; reason: string };
	expect("running cold-DO diagnostic observes without a renewal", [diagnostic.status, emptyDiagnostic.available, emptyDiagnostic.reason], [200, false, "no_attempt"]);
	expect("diagnostic-only wake changes no lifecycle or sealed state", JSON.stringify(unchanged()) === JSON.stringify(beforeDiagnostic), true);
	expect("renewal diagnostics require admin proof", (await call("GET", `/admin/instances/${id}/google-renewal`, { "x-keyring-caller": "caller-secret" })).status, 401);
	const instance = objects.get(id)! as any;
	instance.starting = true;
	const beforeStarting = [...unchanged(), dc.diagnosticCalls];
	diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	expect("starting container is unavailable without a container call", await diagnostic.json(), { available: false, reason: "starting" });
	expect("starting diagnostic has no side effects", JSON.stringify([...unchanged(), dc.diagnosticCalls]) === JSON.stringify(beforeStarting), true);
	instance.starting = false;

	const phases = ["configuration", "controller_wait", "sdk_execution", "persistence", "token_validation"];
	const safeAttempt = {
		available: true, process_started_at: "2026-01-01T00:00:00Z",
		attempt: { started_at: "2026-01-01T00:00:01Z", completed_at: "2026-01-01T00:00:02Z",
			phase: "sdk_execution", outcome: "timeout", duration_ms: 1000,
			process: { available: true, cpu_time_ms: 42, exit_code: -1, signal: 9 },
			steps: phases.map(phase => ({ phase, duration_ms: phase === "sdk_execution" ? 1000 : 0,
				outcome: phase === "sdk_execution" ? "timeout" : "not_run" })) },
	};
	const canary = "SYNTHETIC-PRIVATE-DIAGNOSTIC-CANARY";
	dc.diagnosticOverride = () => Response.json({ ...safeAttempt, credential: canary,
		attempt: { ...safeAttempt.attempt, stderr: canary } });
	diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	const projected = await diagnostic.text();
	expect("diagnostics exclude unexpected private provider fields", projected.includes(canary), false);
	expect("diagnostics retain fixed failure metadata", [JSON.parse(projected).attempt.phase, JSON.parse(projected).attempt.process.cpu_time_ms], ["sdk_execution", 42]);
	dc.diagnosticOverride = () => Response.json({ ...safeAttempt, attempt: { ...safeAttempt.attempt, phase: canary } });
	diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	expect("unrecognized failure text is refused without echo", [diagnostic.status, (await diagnostic.text()).includes(canary)], [503, false]);
	dc.diagnosticOverride = () => new Response(canary.repeat(2000));
	diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	expect("oversized diagnostic response is refused without echo", [diagnostic.status, (await diagnostic.text()).includes(canary)], [503, false]);
	let releaseDiagnostic!: () => void;
	let enteredDiagnostic!: () => void;
	const diagnosticEntered = new Promise<void>(resolve => { enteredDiagnostic = resolve; });
	const diagnosticRelease = new Promise<void>(resolve => { releaseDiagnostic = resolve; });
	dc.diagnosticOverride = async () => {
		enteredDiagnostic();
		await diagnosticRelease;
		return Response.json(safeAttempt);
	};
	ds.m.set("lastUsed", Date.now() - 30 * 60_000);
	objects.delete(id);
	const idleDiagnostic = call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	await diagnosticEntered;
	try {
		await objects.get(id)!.alarm();
		const stoppedDuringRead = await Promise.race([dc.proc!.exited.then(() => true), Bun.sleep(5_000).then(() => false)]);
		expect("a pending diagnostic does not pin an idle container", stoppedDuringRead, true);
	} finally {
		releaseDiagnostic();
		await idleDiagnostic;
		dc.diagnosticOverride = null;
	}
	objects.delete(id);
	const beforeStopped = [...unchanged(), dc.diagnosticCalls];
	diagnostic = await call("GET", `/admin/instances/${id}/google-renewal`, ADMIN);
	expect("stopped diagnostic does not start or unlock", await diagnostic.json(), { available: false, reason: "container_not_running" });
	expect("stopped diagnostic preserves storage, idle and container state", JSON.stringify([...unchanged(), dc.diagnosticCalls]) === JSON.stringify(beforeStopped), true);
	// Resume ordinary fixture traffic, not a diagnostic warm-up.
	expect("ordinary service access still restores the stopped fixture", (await call("GET", `/admin/instances/${id}/services`, ADMIN)).status, 200);
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
	expect("after a restart, the daily limit holds", (await call("GET", `/p/${id}/echo/x5`, P)).status, 429);

	// Concurrent calls on a stopped container start it once (review P3).
	await containers.get(id)!.destroy();
	objects.get(id)!["ready" as never] = null as never;
	const before = starts;
	const both = await Promise.all([call("GET", `/p/${id}/echo/z1`, P), call("GET", `/p/${id}/echo/z2`, P)]);
	expect("two calls on a stopped container: one start", [both.map((x) => x.status), starts - before], [[429, 429], 1]);

	r = await call("POST", `/admin/instances/${id}/role-token`, ADMIN);
	const token2 = ((await r.json()) as { role_token: string }).role_token;
	expect("rotated token retains provisioned Drive grant", (await call("GET", `/p/${id}/google-me-drive/about`, { ...P, "x-keyring-token": token2 })).status, 503);
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

	// A pilot secret must work only in its selected keyring, including an
	// existing keyring restarted from sealed state. Other global clients stay usable.
	{
		const provider = serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req) {
				const path = new URL(req.url).pathname;
				if (req.method !== "POST" || !["/pilot/token", "/global/token"].includes(path)) return new Response("", { status: 404 });
				const form = await req.formData();
				const pilot = path === "/pilot/token";
				if (form.get("client_id") !== (pilot ? "pilot-client" : "global-client") ||
					form.get("client_secret") !== (pilot ? "synthetic-owner-only-secret" : "client-secret-value")) {
					return Response.json({ error: "invalid_client" }, { status: 400 });
				}
				return Response.json({ refresh_token: "synthetic-refresh", access_token: "synthetic-access", token_type: "Bearer", expires_in: 3600 });
			},
		});
		try {
			const pilot = await (await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "pilot" }))).json() as { keyring_id: string; role_token: string };
			const other = await (await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "other" }))).json() as { keyring_id: string; role_token: string };
			env.OAUTH_CLIENT_SECRETS_BY_INSTANCE = JSON.stringify({ [pilot.keyring_id]: { GOOGLE_CLIENT_SECRET: "synthetic-owner-only-secret" } });
			for (const person of [pilot, other]) {
				await containers.get(person.keyring_id)!.destroy();
				objects.delete(person.keyring_id);
			}
			const configure = async (id: string, mode: "pilot" | "global") => {
				const response = await call("PUT", `/admin/instances/${id}/services/gmail`, ADMIN, JSON.stringify({
					service: {
						base: `http://127.0.0.1:${api.port}`, key: "GMAIL_REFRESH", auth: "oauth2",
						oauth2: {
							token_url: `http://127.0.0.1:${provider.port}/${mode}/token`,
							client_id: `${mode}-client`, client_secret_key: "GOOGLE_CLIENT_SECRET",
							auth_url: "https://accounts.example.com/auth", scopes: ["read"],
						},
					},
				}));
				expect(`${mode} OAuth service configured`, response.status, 200);
			};
			const connect = async (id: string) => {
				const link = await (await call("POST", `/admin/instances/${id}/links`, ADMIN, JSON.stringify({ service: "gmail" }))).json() as { url: string };
				const start = await call("POST", new URL(link.url).pathname, FORM, "");
				const redirect = new URL(start.headers.get("location")!);
				const cookie = start.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
				const query = new URLSearchParams({ state: redirect.searchParams.get("state")!, code: "synthetic-code" });
				return call("GET", `/connect/callback?${query}`, { cookie });
			};
			const read = (person: typeof pilot) => call("GET", `/p/${person.keyring_id}/gmail/read`, {
				"x-keyring-caller": "caller-secret", "x-keyring-token": person.role_token,
			});
			await configure(pilot.keyring_id, "pilot");
			await configure(other.keyring_id, "global");
			expect("selected keyring can consent with its private pilot client", (await connect(pilot.keyring_id)).status, 200);
			expect("selected keyring can refresh and use the pilot grant", (await read(pilot)).status, 200);
			expect("other keyring retains its existing global client", (await connect(other.keyring_id)).status, 200);
			expect("other keyring can use its global grant", (await read(other)).status, 200);
			await containers.get(pilot.keyring_id)!.destroy();
			objects.delete(pilot.keyring_id);
			expect("pilot secret and grant survive sealed cold restore", (await read(pilot)).status, 200);
			// Even copying the pilot's service settings must not copy its secret.
			await configure(other.keyring_id, "pilot");
			expect("unselected keyring cannot consent with the pilot client", (await connect(other.keyring_id)).status, 502);
			expect("unselected keyring cannot reuse its old grant as the pilot", (await read(other)).status, 503);
			const savedSettings = env.OAUTH_CLIENT_SECRETS_BY_INSTANCE;
			env.OAUTH_CLIENT_SECRETS_BY_INSTANCE = "synthetic-private-secret-not-json";
			await containers.get(pilot.keyring_id)!.destroy();
			objects.delete(pilot.keyring_id);
			const settingsFailure = await call("GET", `/admin/instances/${pilot.keyring_id}/services`, ADMIN);
			expect("malformed secret settings fail without quoting secret text",
				[settingsFailure.status, (await settingsFailure.text()).includes("synthetic-private-secret")], [502, false]);
			env.OAUTH_CLIENT_SECRETS_BY_INSTANCE = savedSettings;
			objects.delete(pilot.keyring_id);
			expect("corrected protected settings restore pilot access", (await read(pilot)).status, 200);
			for (const person of [pilot, other]) await call("DELETE", `/admin/instances/${person.keyring_id}`, ADMIN);
		} finally {
			env.OAUTH_CLIENT_SECRETS_BY_INSTANCE = "{}";
			provider.stop(true);
		}
	}

	// Review of e61b020: a fresh object (evicted, redeployed) must not stop a
	// running container on its first alarm, and an alarm during a start must
	// not drop that start.
	{
		r = await call("POST", "/admin/instances", ADMIN, JSON.stringify({ label: "fresh" }));
		const kf = ((await r.json()) as { keyring_id: string }).keyring_id;
		objects.delete(kf); // a new object instance, same storage and running container
		storages.get(kf)!.m.delete("lastUsed"); // as for a keyring made before lastUsed was kept
		await env.KEYRING.get(kf).alarm();
		await Bun.sleep(200); // a signalled process takes a moment to exit
		expect("first alarm of a fresh object keeps a running container", containers.get(kf)!.running, true);
		// Evicted again, its last call 11 minutes ago (kept in storage): the
		// alarm of the new object stops the idle container.
		objects.delete(kf);
		storages.get(kf)!.m.set("lastUsed", Date.now() - 11 * 60 * 1000);
		await env.KEYRING.get(kf).alarm();
		await Bun.sleep(200);
		expect("an evicted object still stops an idle container", containers.get(kf)!.running, false);
		objects.delete(kf);

		await containers.get(kf)!.destroy();
		objects.delete(kf);
		const o = env.KEYRING.get(kf);
		const startsAt = starts;
		const wake = call("GET", `/admin/instances/${kf}/services`, ADMIN);
		await Bun.sleep(5); // start() issued; the fake turns running after 20 ms
		await o.alarm();
		// A call arriving after that alarm must join the start in progress.
		const [w, w2] = await Promise.all([wake, call("GET", `/admin/instances/${kf}/services`, ADMIN)]);
		expect("alarm during a start", [w.status, w2.status, starts - startsAt, containers.get(kf)!.running], [200, 200, 1, true]);
		await call("DELETE", `/admin/instances/${kf}`, ADMIN);
	}

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
