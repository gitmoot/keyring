package dashboard

import "html/template"

// Templates only. No inline scripts or styles: the admin server's CSP allows
// neither (the one script is /static/app.js). No template ever receives a key
// value. Layout is one column that works from a phone up; see admin's CSS.
var pages = template.Must(template.New("pages").Parse(`
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Keyring</title><link rel="stylesheet" href="/static/app.css"><script src="/static/app.js" defer></script></head><body>
<header class="top"><div class="wrap">
<a class="brand" href="/keys">Keyring</a>
<nav class="tabs"><a href="/keys"{{if or (eq .Page "keys") (eq .Page "key") (eq .Page "newkey")}} class="on"{{end}}>Keys</a><a href="/access"{{if or (eq .Page "access") (eq .Page "cell") (eq .Page "agent") (eq .Page "newagent") (eq .Page "token")}} class="on"{{end}}>Agents</a></nav>
<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="link">Log out</button></form>
</div></header><main class="wrap">{{end}}
{{define "bottom"}}</main></body></html>{{end}}

{{define "password"}}<label class="pw">Dashboard password<input type="password" name="password" autocomplete="current-password" required placeholder="asked on every change"></label>{{end}}

{{define "status"}}<span class="pill {{.StatusClass}}">{{.Status}}</span>{{end}}

{{define "keys"}}{{template "top" .}}
{{if eq .Notice "deleted"}}<p class="notice">Key deleted.</p>{{end}}
<div class="head"><h1>Keys</h1><a class="btn" href="/new/key">Add key</a></div>
<form method="get" action="/keys" class="search"><input type="search" name="q" value="{{.Query}}" placeholder="Search keys or services" aria-label="Search"></form>
<ul class="list">
{{range .Rows}}<li><a class="item" href="/keys/{{.Name}}">
<span class="name">{{.Name}}</span>{{template "status" .}}
<span class="meta">{{if .Services}}{{range $i, $s := .Services}}{{if $i}}, {{end}}{{$s}}{{end}}{{else}}not connected{{end}}
{{if .UsedBy}} · {{len .UsedBy}} agent{{if ne (len .UsedBy) 1}}s{{end}}{{end}}
 · {{with .LastUsed}}used {{.}}{{else}}never used{{end}}{{if .CallsToday}} · {{.CallsToday}} today{{end}}</span>
</a></li>
{{else}}<li class="empty">No keys{{if .Query}} match “{{.Query}}”{{end}}.</li>{{end}}
</ul>
{{template "bottom"}}{{end}}

{{define "newkey"}}{{template "top" .}}
<div class="head"><h1>Add a key</h1></div>
<div class="card">
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/keys"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name<input name="name" value="{{.Name}}" required pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="OPENROUTER_API_KEY" autocapitalize="characters" autocomplete="off" spellcheck="false"></label>
<label>Value<input type="password" name="value" autocomplete="off" required placeholder="paste it here; it is never shown again"></label>
{{template "password" .}}
<div class="actions"><button>Add key</button><a class="btn ghost" href="/keys">Cancel</a></div>
</form></div>
<p class="hint">Just the name and the value. Which API it is for can be set on the key's page, now or later.</p>
{{template "bottom"}}{{end}}

{{define "key"}}{{template "top" .}}
{{if eq .Notice "added"}}<p class="notice">Key added.</p>{{else if eq .Notice "connected"}}<p class="notice">Connected. Give agents access under Agents.</p>{{else if .Notice}}<p class="notice">Key {{.Notice}}.</p>{{end}}
{{if eq .Error "password"}}<p class="error">Enter your dashboard password to do that.</p>{{else if eq .Error "value"}}<p class="error">Paste the new value, on one line.</p>{{else if eq .Error "in-use"}}<p class="error">Agents still use this key. Tick the box to delete it anyway.</p>{{else if eq .Error "no-test"}}<p class="error">No service using this key has a test request.</p>{{else if eq .Error "no-value"}}<p class="error">This key has no stored value.</p>{{else if eq .Error "changed"}}<p class="error">The key was replaced or deleted during the test, so its result was not kept. Test again.</p>{{end}}
<div class="head"><a class="back" href="/keys">Keys</a><h1 class="mono">{{.Row.Name}}</h1>{{template "status" .Row}}</div>
<div class="card"><dl>
<dt>Value</dt><dd>{{if .Row.HasValue}}<span class="masked">••••••••</span> <span class="mute">never shown</span>{{else}}none stored{{end}}</dd>
<dt>Services</dt><dd>{{range .Row.Services}}<span class="chip">{{.}}</span>{{else}}<span class="mute">not connected yet</span>{{end}}</dd>
<dt>Agents</dt><dd>{{range .Row.UsedBy}}<a class="chip" href="/agents/{{.}}">{{.}}</a>{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Last used</dt><dd>{{with .Row.LastUsed}}{{.}}{{else}}never{{end}} · {{.Row.CallsToday}} today</dd>
{{if not .Meta.CheckedAt.IsZero}}<dt>Tested</dt><dd>{{.Meta.CheckedAt.Format "2006-01-02 15:04"}} UTC</dd>{{end}}
</dl>
{{if .Testable}}<form method="post" action="/keys/{{.Row.Name}}/test" class="inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Test now</button></form>{{end}}
</div>

<details class="card"{{if or (not .Row.Services) .ConnectError}} open{{end}}><summary>{{if .Row.Services}}Connect to another service{{else}}Connect to a service{{end}}</summary>
{{with .ConnectError}}<p class="error">{{.}}</p>{{end}}
<form method="get" action="/keys/{{.Row.Name}}" class="presetpick"><label>Which API?<select name="preset" data-autosubmit>
<option value=""{{if eq .Connect.Preset ""}} selected{{end}}>Other (fill in below)</option>
{{range .Presets}}<option value="{{.ID}}"{{if eq .ID $.Connect.Preset}} selected{{end}}>{{.Label}}</option>{{end}}
</select></label><noscript><button class="ghost">Use</button></noscript></form>
<form method="post" action="/keys/{{.Row.Name}}/connect"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="preset" value="{{.Connect.Preset}}">
<details{{if or (eq .Connect.Preset "") .ConnectError}} open{{end}}><summary>Settings{{if .Connect.Preset}}: {{.Connect.Base}}{{end}}</summary>
<label>Service name<input name="service" value="{{.Connect.Service}}" placeholder="e.g. openrouter" autocapitalize="none" spellcheck="false"></label>
<label>Base URL<input name="base" value="{{.Connect.Base}}" placeholder="e.g. https://api.example.com" inputmode="url" autocapitalize="none" spellcheck="false"></label>
<label>Key sent as<select name="auth">
<option value="bearer"{{if eq .Connect.Auth "bearer"}} selected{{end}}>Authorization: Bearer</option>
<option value="header"{{if eq .Connect.Auth "header"}} selected{{end}}>a header</option>
<option value="query"{{if eq .Connect.Auth "query"}} selected{{end}}>a query parameter</option></select></label>
<div class="two"><label>Header (if a header)<input name="header" value="{{.Connect.Header}}" placeholder="e.g. X-Api-Key" autocapitalize="none"></label>
<label>Parameter (if a query)<input name="param" value="{{.Connect.Param}}" placeholder="e.g. api_key" autocapitalize="none"></label></div>
<label>Test request (optional, a harmless GET)<input name="test_path" value="{{.Connect.TestPath}}" placeholder="e.g. /v1/models" autocapitalize="none" spellcheck="false"></label>
</details>
<details><summary>Or paste settings from an agent</summary>
<label>JSON like {"service":"x","base":"https://…","auth":"bearer","test_path":"/…"}<textarea name="pasted" spellcheck="false" autocapitalize="none"></textarea></label>
</details>
{{template "password" .}}
<div class="actions"><button>Connect</button></div>
</form></details>

<div class="card"><h2>Replace value</h2><form method="post" action="/keys/{{.Row.Name}}/replace"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>New value<input type="password" name="value" autocomplete="off" required></label>{{template "password" .}}<div class="actions"><button>Replace</button></div></form></div>

<details class="card danger"><summary>Leaked or no longer needed</summary>
<form method="post" action="/keys/{{.Row.Name}}/leaked"><input type="hidden" name="csrf" value="{{.CSRF}}"><p class="mute">Marking it leaked shows a warning until you replace it.</p>{{template "password" .}}<div class="actions"><button class="ghost">Mark as leaked</button></div></form>
<hr>
<form method="post" action="/keys/{{.Row.Name}}/delete"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Row.UsedBy}}<label class="check"><input type="checkbox" name="confirm_in_use" value="yes"> Delete even though {{range $i, $r := .Row.UsedBy}}{{if $i}}, {{end}}{{$r}}{{end}} {{if eq (len .Row.UsedBy) 1}}uses{{else}}use{{end}} it</label>{{end}}
{{template "password" .}}<div class="actions"><button class="danger">Delete key</button></div></form>
</details>
{{template "bottom"}}{{end}}

{{define "error"}}{{template "top" .}}<p class="error">{{.Error}}</p><p><a href="/keys">Back to keys</a></p>{{template "bottom"}}{{end}}

{{define "access"}}{{template "top" .}}
{{with .Notice}}<p class="notice">{{.}}</p>{{end}}
<div class="head"><h1>Agents</h1><a class="btn" href="/new/agent">Add agent</a></div>
{{range .Rows}}<div class="card agent">
<div class="agenthead"><a class="name" href="/agents/{{.Role}}">{{.Role}}</a>{{if .Ended}}<span class="pill warn">ended</span>{{end}}<span class="mute">{{.CallsToday}} call{{if ne .CallsToday 1}}s{{end}} today</span></div>
<ul class="grants">{{range .Cells}}<li><a class="grant{{if .Ended}} ended{{end}}" href="/access/{{.Role}}/{{.Service}}"><span class="svc">{{.Service}}</span><span class="what">{{.Label}}</span><span class="mute">{{.Detail}}</span></a></li>
{{else}}<li class="mute">No services yet.</li>{{end}}</ul>
{{if .Off}}<form method="get" action="/access/{{.Role}}/-" class="add" data-pathpick><select name="service" aria-label="Add a service to {{.Role}}"><option value="">Add a service…</option>{{range .Off}}<option>{{.}}</option>{{end}}</select><noscript><button class="ghost">Open</button></noscript></form>{{end}}
</div>
{{else}}<p class="empty card">No agents yet. Add one, then give it services.</p>{{end}}
{{template "bottom"}}{{end}}

{{define "cell"}}{{template "top" .}}
<div class="head"><a class="back" href="/agents/{{.Form.Role}}">{{.Form.Role}}</a><h1>{{.Form.Service}}</h1></div>
<div class="card">
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/access/{{.Form.Role}}/{{.Form.Service}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="switch"><input type="checkbox" name="on" value="yes"{{if .Form.On}} checked{{end}}> <span>{{.Form.Role}} may use {{.Form.Service}}</span></label>
<p class="lbl">Allowed</p>
<div class="seg" role="radiogroup" aria-label="Allowed methods">
<label><input type="radio" name="mode" value="read"{{if eq .Form.Mode "read"}} checked{{end}}><span>Read only</span></label>
<label><input type="radio" name="mode" value="full"{{if eq .Form.Mode "full"}} checked{{end}}><span>Full</span></label>
<label><input type="radio" name="mode" value="custom"{{if eq .Form.Mode "custom"}} checked{{end}}><span>Custom</span></label>
</div>
<div class="methods">{{$f := .Form}}{{range .AllMethods}}<label class="check"><input type="checkbox" name="method" value="{{.}}"{{if $f.Has .}} checked{{end}}> {{.}}</label>{{end}}</div>
<p class="hint">Read only: GET and HEAD. Full: every method.</p>
<label>Allowed paths, one per line<textarea name="paths" spellcheck="false" autocapitalize="none">{{.Form.Paths}}</textarea></label>
<p class="hint">/ allows everything; /v1 allows /v1 and below.</p>
<div class="two"><label>Daily limit<input name="daily" inputmode="numeric" value="{{.Form.Daily}}" placeholder="none"></label>
<label>Ends on (UTC)<input type="date" name="expires" value="{{.Form.Expires}}"></label></div>
{{template "password" .}}<div class="actions"><button>Save</button><a class="btn ghost" href="/agents/{{.Form.Role}}">Cancel</a></div></form></div>
{{template "bottom"}}{{end}}

{{define "newagent"}}{{template "top" .}}
<div class="head"><a class="back" href="/access">Agents</a><h1>Add an agent</h1></div>
<div class="card">
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/agents"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name<input name="name" value="{{.Name}}" required pattern="[A-Za-z0-9][A-Za-z0-9._\-]*" placeholder="aste-screener" autocapitalize="none" spellcheck="false"></label>
<label>Token fingerprint from the agent (optional)<input name="fingerprint" value="{{.Fingerprint}}" placeholder="64 hex characters" autocapitalize="none" autocomplete="off" spellcheck="false" pattern="[0-9a-fA-F]{64}"></label>
<p class="hint">If the agent made its own token, paste the sha256 it gives you: the token then never leaves its machine. Leave it empty and the next page shows a new token once. The agent starts with no services.</p>
{{template "password" .}}<div class="actions"><button>Add agent</button></div></form></div>
{{template "bottom"}}{{end}}

{{define "token"}}{{template "top" .}}
<div class="head"><h1>Token for {{.Role}}</h1></div>
<div class="card">
<p class="warnbox">Shown once. Copy it now: it is not stored here.{{if .Replaced}} The old token stopped working just now.{{end}}</p>
<div class="token"><input id="token" readonly autocomplete="off" value="{{.Token}}"><button type="button" data-copy="token">Copy</button></div>
<p class="hint">On the machine that calls the keyring, save it as <code>{{.File}}</code> (mode 600), or send it to the agent that sets this up.</p>
<div class="actions"><a class="btn" href="/agents/{{.Role}}">Give it services</a></div></div>
{{template "bottom"}}{{end}}

{{define "agent"}}{{template "top" .}}
{{if .Added}}<p class="notice">Agent added with its own token. Give it services below.</p>{{end}}
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<div class="head"><a class="back" href="/access">Agents</a><h1>{{.Role}}</h1>{{if .Ended}}<span class="pill warn">ended</span>{{end}}</div>
<div class="card"><h2>Services</h2>
<ul class="grants">{{range .Services}}<li><a class="grant" href="/access/{{$.Role}}/{{.Service}}"><span class="svc">{{.Service}}</span><span class="what">{{.Label}}</span></a></li>{{else}}<li class="mute">None yet.</li>{{end}}</ul>
{{if .Off}}<form method="get" action="/access/{{.Role}}/-" class="add" data-pathpick><select name="service" aria-label="Add a service"><option value="">Add a service…</option>{{range .Off}}<option>{{.}}</option>{{end}}</select><noscript><button class="ghost">Open</button></noscript></form>{{end}}
</div>
<div class="card"><dl><dt>Ends</dt><dd>{{with .Expires}}{{.}}{{else}}never{{end}}</dd><dt>Token file</dt><dd><code>{{.File}}</code></dd></dl></div>
<details class="card"><summary>Make a new token</summary><form method="post" action="/agents/{{.Role}}/token"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="current" value="{{.Current}}">
<p class="mute">Shown once. The old token stops working at once.</p>{{template "password" .}}<div class="actions"><button>Make a new token</button></div></form></details>
<details class="card danger"><summary>Revoke</summary><form method="post" action="/agents/{{.Role}}/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="check"><input type="checkbox" name="confirm" value="yes" required> Remove {{.Role}} and all its access; its calls fail at once</label>
{{template "password" .}}<div class="actions"><button class="danger">Revoke agent</button></div></form></details>
{{template "bottom"}}{{end}}
`))
