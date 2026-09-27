package dashboard

import "html/template"

// Templates only. No inline scripts or styles: the admin server's CSP allows
// neither. No template ever receives a key value.
var pages = template.Must(template.New("pages").Parse(`
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Keyring</title><link rel="stylesheet" href="/static/app.css"></head><body>
<header class="top"><h1>Keyring</h1>
<nav class="tabs"><a href="/keys"{{if or (eq .Page "keys") (eq .Page "key") (eq .Page "newkey")}} class="on"{{end}}>Keys</a></nav>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Log out</button></form></header><main>{{end}}
{{define "bottom"}}</main></body></html>{{end}}

{{define "password"}}<label>Your dashboard password (asked on every change)<input type="password" name="password" autocomplete="current-password" required></label>{{end}}

{{define "keys"}}{{template "top" .}}
{{if .Notice}}<p class="notice">Key {{.Notice}}.</p>{{end}}
<div class="bar"><form method="get" action="/keys"><input type="search" name="q" value="{{.Query}}" placeholder="Search keys or services"><button class="ghost">Search</button></form><a class="btn" href="/new/key">+ Add key</a></div>
<table><tr><th>Key</th><th>Service</th><th>Value</th><th>Status</th><th>Used by</th><th>Last used</th><th>Calls today</th></tr>
{{range .Rows}}<tr><td><a href="/keys/{{.Name}}"><code>{{.Name}}</code></a></td>
<td>{{range .Services}}<span class="chip">{{.}}</span>{{else}}<span class="mute">—</span>{{end}}</td>
<td>{{if .HasValue}}<span class="masked">••••••••</span>{{else}}<span class="mute">none</span>{{end}}</td>
<td><span class="dot {{.StatusClass}}"></span>{{.Status}}</td>
<td>{{range .UsedBy}}<span class="chip">{{.}}</span>{{else}}<span class="mute">—</span>{{end}}</td>
<td>{{with .LastUsed}}{{.}}{{else}}<span class="mute">never</span>{{end}}</td><td>{{.CallsToday}}</td></tr>
{{else}}<tr><td colspan="7" class="mute">No keys{{if .Query}} match “{{.Query}}”{{end}}.</td></tr>{{end}}
</table>
{{template "bottom"}}{{end}}

{{define "newkey"}}{{template "top" .}}
<div class="card"><h2>Add a key</h2>
{{with .Error}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/keys"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name (like OPENROUTER_API_KEY)<input name="name" value="{{.Form.Name}}" required pattern="[A-Za-z_][A-Za-z0-9_]*"></label>
<label>Value (shown once here, never again)<input type="password" name="value" autocomplete="off" required></label>
<label>Used by
<select name="mode">
<option value="new"{{if eq .Form.Mode "new"}} selected{{end}}>a new service (fill in below)</option>
<option value="existing"{{if eq .Form.Mode "existing"}} selected{{end}}>an existing service (it switches to this key)</option>
<option value="none"{{if eq .Form.Mode "none"}} selected{{end}}>no service yet</option>
</select></label>
<label>Existing service<select name="existing">{{range .Services}}<option{{if eq . $.Form.Existing}} selected{{end}}>{{.}}</option>{{end}}</select></label>
<div class="row"><label>New service name<input name="svc_name" value="{{.Form.SvcName}}" placeholder="openrouter"></label><label>Base URL<input name="base" value="{{.Form.Base}}" placeholder="https://openrouter.ai"></label></div>
<div class="row"><label>Key sent as<select name="auth">
<option value="bearer"{{if eq .Form.Auth "bearer"}} selected{{end}}>Authorization: Bearer …</option>
<option value="header"{{if eq .Form.Auth "header"}} selected{{end}}>a header</option>
<option value="query"{{if eq .Form.Auth "query"}} selected{{end}}>a query parameter</option></select></label>
<label>Header name (for “a header”)<input name="header" value="{{.Form.Header}}" placeholder="X-Api-Key"></label>
<label>Parameter (for “a query parameter”)<input name="param" value="{{.Form.Param}}" placeholder="api_key"></label></div>
<div class="row"><label>Test method<select name="test_method"><option{{if eq .Form.TestMethod "GET"}} selected{{end}}>GET</option><option{{if eq .Form.TestMethod "HEAD"}} selected{{end}}>HEAD</option><option{{if eq .Form.TestMethod "POST"}} selected{{end}}>POST</option></select></label>
<label>Test path (a harmless request)<input name="test_path" value="{{.Form.TestPath}}" placeholder="/api/v1/key"></label></div>
{{template "password" .}}
<button>Add key</button> <a href="/keys">Cancel</a></form></div>
{{template "bottom"}}{{end}}

{{define "key"}}{{template "top" .}}
{{if .Notice}}<p class="notice">Key {{.Notice}}.</p>{{end}}
{{if eq .Error "password"}}<p class="error">Enter your dashboard password to do that.</p>{{else if eq .Error "value"}}<p class="error">Paste the new value, on one line.</p>{{else if eq .Error "in-use"}}<p class="error">Agents still use this key. Tick the box to delete it anyway.</p>{{else if eq .Error "no-test"}}<p class="error">No service using this key has a test request.</p>{{else if eq .Error "no-value"}}<p class="error">This key has no stored value.</p>{{else if eq .Error "changed"}}<p class="error">The key was replaced or deleted during the test, so its result was not kept. Test again.</p>{{end}}
<div class="card"><h2><code>{{.Row.Name}}</code></h2><dl>
<dt>Status</dt><dd><span class="dot {{.Row.StatusClass}}"></span>{{.Row.Status}}{{if not .Meta.CheckedAt.IsZero}} <span class="mute">(tested {{.Meta.CheckedAt.Format "2006-01-02 15:04"}} UTC)</span>{{end}}</dd>
<dt>Value</dt><dd>{{if .Row.HasValue}}<span class="masked">••••••••</span> <span class="mute">never shown</span>{{else}}none{{end}}</dd>
<dt>Services</dt><dd>{{range .Row.Services}}<span class="chip">{{.}}</span>{{else}}—{{end}}</dd>
<dt>Used by</dt><dd>{{range .Row.UsedBy}}<span class="chip">{{.}}</span>{{else}}—{{end}}</dd>
<dt>Last used</dt><dd>{{with .Row.LastUsed}}{{.}}{{else}}never{{end}} · {{.Row.CallsToday}} calls today</dd>
</dl></div>
<div class="card"><h2>Test</h2>{{if .Testable}}<form method="post" action="/keys/{{.Row.Name}}/test"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Send the test request</button></form>{{else}}<p class="mute">No service using this key has a test request.</p>{{end}}</div>
<div class="card"><h2>Replace</h2><form method="post" action="/keys/{{.Row.Name}}/replace"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>New value<input type="password" name="value" autocomplete="off" required></label>{{template "password" .}}<button>Replace</button></form></div>
<div class="card"><h2>Leaked?</h2><form method="post" action="/keys/{{.Row.Name}}/leaked"><input type="hidden" name="csrf" value="{{.CSRF}}"><p class="mute">Cleared when you replace it.</p>{{template "password" .}}<button class="ghost">Mark as leaked</button></form></div>
<div class="card"><h2>Delete</h2><form method="post" action="/keys/{{.Row.Name}}/delete"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Row.UsedBy}}<label class="check"><input type="checkbox" name="confirm_in_use" value="yes"> Delete even though {{range $i, $r := .Row.UsedBy}}{{if $i}}, {{end}}{{$r}}{{end}} {{if eq (len .Row.UsedBy) 1}}uses{{else}}use{{end}} it</label>{{end}}
{{template "password" .}}<button class="danger">Delete key</button></form></div>
{{template "bottom"}}{{end}}

{{define "error"}}{{template "top" .}}<p class="error">{{.Error}}</p><p><a href="/keys">Back to keys</a></p>{{template "bottom"}}{{end}}
`))
