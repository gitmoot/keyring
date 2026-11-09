package dashboard

import "html/template"

// Templates only. No inline scripts or styles: the admin server's CSP allows
// neither (the one script is /static/app.js). No template ever receives a key
// value. Layout is one column that works from a phone up; see admin's CSS.
var pages = template.Must(template.New("pages").Parse(`
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Keyring</title><link rel="stylesheet" href="/static/app.css"><script src="/static/app.js" defer></script></head><body class="console">
<aside class="side"><a class="logo" href="/keys"><i></i>Keyring</a>
<nav class="sidenav" aria-label="Sections">
<a href="/keys" class="nav{{if or (eq .Page "keys") (eq .Page "key") (eq .Page "newkey") (eq .Page "service")}} on{{end}}">Keys<span class="n">{{.Nav.Keys}}</span></a>
<a href="/access" class="nav{{if or (eq .Page "access") (eq .Page "cell") (eq .Page "agent") (eq .Page "newagent") (eq .Page "token")}} on{{end}}">Agents<span class="n">{{.Nav.Agents}}</span></a>
<a href="/projects" class="nav{{if or (eq .Page "projects") (eq .Page "project")}} on{{end}}">Projects<span class="n">{{.Nav.Projects}}</span></a>
<a href="/access#requests" class="nav">Requests<span class="n{{if .PendingCount}} hot{{end}}">{{.PendingCount}}</span></a>
</nav>
{{with .Nav.ProjectList}}<p class="sec">Projects</p><nav class="sidenav projects" aria-label="Projects">{{range .}}<a href="/projects/{{.Name}}" class="nav"><i class="dot {{.Dot}}"></i>{{.Name}}<span class="n">{{.Services}}</span></a>{{end}}</nav>{{end}}
<div class="me">{{with .Nav.Version}}<span class="ver">{{.}}</span>{{end}}<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="link">Log out</button></form></div>
</aside>
<main class="body{{if or (eq .Page "keys") (eq .Page "access")}} wide{{end}}">{{end}}
{{define "bottom"}}</main></body></html>{{end}}

{{define "password"}}<label class="pw">Dashboard password<input type="password" name="password" autocomplete="current-password" required placeholder="asked on every change"></label>{{end}}

{{define "thead"}}<thead><tr>{{range .}}<th{{with .Class}} class="{{.}}"{{end}}>{{if .Href}}<a href="{{.Href}}">{{.Label}}{{with .Arrow}} <span class="arrow">{{.}}</span>{{end}}</a>{{else}}{{.Label}}{{end}}</th>{{end}}</tr></thead>{{end}}

{{define "status"}}<span class="pill {{.StatusClass}}">{{.Status}}</span>{{end}}

{{define "projectfilters"}}{{if .}}<nav class="filters" aria-label="Project">{{range .}}<a class="f{{if .On}} on{{end}}" href="{{.Href}}">{{.Label}}{{if ge .Count 0}} <b>{{.Count}}</b>{{end}}</a>{{end}}</nav>{{end}}{{end}}
{{define "keys"}}{{template "top" .}}
{{if eq .Notice "deleted"}}<p class="notice">Key deleted.</p>{{end}}
<div class="bar"><h1>Keys <span class="count">{{len .Rows}}</span></h1>
<form method="get" action="/keys" class="tsearch">{{with .Project}}<input type="hidden" name="project" value="{{.}}">{{end}}{{with .Show}}<input type="hidden" name="show" value="{{.}}">{{end}}{{with .Sort}}<input type="hidden" name="sort" value="{{.}}">{{end}}{{if .Desc}}<input type="hidden" name="desc" value="1">{{end}}<input type="search" name="q" value="{{.Query}}" placeholder="Search keys or APIs" aria-label="Search"></form>
<a class="btn" href="/new/key">Add key</a></div>
<div class="stats">
<div class="stat"><small>Keys</small><b>{{.Stats.Keys}}</b></div>
<div class="stat"><small>Calls today</small><b>{{.Stats.CallsToday}}</b></div>
<div class="stat"><small>Failing</small><b>{{.Stats.Failing}}</b>{{with .Stats.NoValue}}<span class="sub">+ {{.}} without a value</span>{{end}}</div>
<a class="stat" href="/access#requests"><small>Waiting for you</small><b>{{.PendingCount}}</b><span class="sub">access requests</span></a>
</div>
{{template "projectfilters" .ProjectFilters}}
<nav class="filters" aria-label="Show">{{$q := .Query}}{{$p := .Project}}{{range .Filters}}<a class="f{{with .Class}} {{.}}{{end}}{{if .On}} on{{end}}" href="/keys?{{if .ID}}show={{.ID}}{{end}}{{if $q}}{{if .ID}}&amp;{{end}}q={{$q}}{{end}}{{if $p}}{{if or .ID $q}}&amp;{{end}}project={{$p}}{{end}}">{{.Label}} <b>{{.Count}}</b></a>{{end}}</nav>
<div class="tablewrap"><table class="t">
{{template "thead" .Columns}}
<tbody>{{range .Rows}}<tr>
<td class="first"><a class="kname" href="/keys/{{.Name}}">{{.Name}}</a>{{range .Projects}} <a class="chip" href="/projects/{{.}}">{{.}}</a>{{end}}</td>
<td>{{if .Services}}{{.Provider}}<div class="sub">{{range $i, $s := .Services}}{{if $i}}, {{end}}{{$s}}{{end}}</div>{{else}}<a class="sub link" href="/keys/{{.Name}}">not connected · connect</a>{{end}}</td>
<td>{{template "status" .}}</td>
<td class="chips">{{range .Grants}}<a class="chip {{if .Full}}full{{else}}lim{{end}}" href="/agents/{{.Role}}" title="{{if .Full}}full access{{else}}limited access{{end}}">{{.Role}}</a>{{else}}<span class="mute">nobody</span>{{end}}</td>
<td>{{with .LastUsed}}{{.}}{{else}}<span class="mute">never</span>{{end}}</td>
<td class="num">{{.CallsToday}}</td>
<td><span class="spark" title="{{.WeekTotal}} calls in 7 days">{{range .Spark}}<i class="h{{.}}"></i>{{end}}</span></td>
<td class="mute">{{with .Updated}}{{.}}{{else}}—{{end}}</td>
</tr>{{else}}<tr><td colspan="8" class="empty">No keys{{if .Query}} match “{{.Query}}”{{end}}{{if .Show}} in this group{{end}}.</td></tr>{{end}}</tbody>
</table></div>
<p class="hint">Click a key to test, replace or delete it. Click a column to sort. Calls today count every attempt, refused ones too. Key values are never shown.</p>
{{if .GoogleAccounts}}<h2>Host Google accounts</h2>
<p class="hint">Managed on the keyring host with gcloud, not stored keys. Status is from the last token check, not a live permission test. Manage each service's grants under Agents; signing in grants no agent access.</p>
<div class="tablewrap"><table class="t"><thead><tr><th>Binding</th><th>Google account</th><th>Services</th><th>Credential status</th><th>Token expires (UTC)</th></tr></thead><tbody>
{{range .GoogleAccounts}}<tr><td>{{.Name}}</td><td>{{.Account}}</td><td>{{range $i, $s := .Services}}{{if $i}}, {{end}}{{$s}}{{end}}</td><td class="google-status">{{.Status}}
{{if .HistoryUnavailable}}<p class="error">Protected renewal history is unavailable. Inspect host storage; new failures may not survive restart.</p>{{end}}
{{with .LastSuccess}}<p class="hint">Last successful renewal (UTC): {{.}}</p>{{end}}
{{if .History}}<details><summary>Recent renewal incidents ({{len .History}})</summary>
{{range .History}}<p><strong>{{.Outcome}}</strong> — {{.Failure.Category}} / {{.Failure.Stage}}<br>
First failure: {{.FirstFailure.UTC.Format "2006-01-02T15:04:05Z"}}; last failure: {{.LastFailure.UTC.Format "2006-01-02T15:04:05Z"}}; attempts: {{.Attempts}}.
{{if not .RecoveredAt.IsZero}}Recovered: {{.RecoveredAt.UTC.Format "2006-01-02T15:04:05Z"}}.{{end}}<br>
{{.Failure.Error}} Action: <code>{{.Failure.Recovery}}</code>.
{{with .Failure.Evidence}} Evidence: {{range $i, $e := .}}{{if $i}}, {{end}}{{$e}}{{end}}.{{end}}</p>{{end}}
</details>{{end}}</td><td>{{.Expires}}</td></tr>{{end}}
</tbody></table></div>{{end}}
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
{{if eq .Error "password"}}<p class="error">Enter your dashboard password to do that.</p>{{else if eq .Error "value"}}<p class="error">Paste the new value, on one line.</p>{{else if eq .Error "value-control"}}<p class="error">The value has a line break or control character inside it, so it was not saved. Paste only the key itself.</p>{{else if eq .Error "in-use"}}<p class="error">Agents still use this key. Tick the box to delete it anyway.</p>{{else if eq .Error "no-test"}}<p class="error">No service using this key has a test request.</p>{{else if eq .Error "no-value"}}<p class="error">This key has no stored value.</p>{{else if eq .Error "changed"}}<p class="error">The key was replaced or deleted during the test, so its result was not kept. Test again.</p>{{end}}
<div class="head"><a class="back" href="/keys">Keys</a><h1 class="mono">{{.Row.Name}}</h1>{{template "status" .Row}}</div>
<div class="card"><dl>
<dt>Value</dt><dd>{{if .Row.HasValue}}<span class="masked">••••••••</span> <span class="mute">never shown</span>{{else}}none stored{{end}}</dd>
<dt>Services</dt><dd>{{range .Row.Services}}<a class="chip" href="/services/{{.}}">{{.}}</a>{{else}}<span class="mute">not connected yet</span>{{end}}</dd>
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
<label>Pinned certificate SHA-256 (optional, only for a self-signed https service)<input name="tls_pin_sha256" value="{{.Connect.TLSPin}}" placeholder="64 hex characters" autocapitalize="none" spellcheck="false"></label>
</details>
<details><summary>Or paste settings from an agent</summary>
<label>JSON like {"service":"x","base":"https://…","auth":"bearer","test_path":"/…"}<textarea name="pasted" spellcheck="false" autocapitalize="none"></textarea></label>
<p class="hint">For an API that needs a second secret, add it as its own key first, then name it in extra_headers: {"Modal-Secret":"MODAL_PROXY_SECRET"} (header name to key name, never a value; up to two). Optional fixed_headers sets up to two nonsecret header values, for example {"CF-R2-Jurisdiction":"default"}. These override caller values and are not redacted from responses. Never put credentials here.</p>
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
<p>Delete only the stored value to keep the service settings for later, or remove this key completely.</p>
{{if .Row.Services}}<p>Remove completely also deletes these services and all agents' access to them: {{range $i, $s := .Row.Services}}{{if $i}}, {{end}}<strong>{{$s}}</strong>{{end}}. Other stored keys are kept.</p>{{end}}
{{if .Row.UsedBy}}<label class="check"><input type="checkbox" name="confirm_in_use" value="yes"> Delete even though {{range $i, $r := .Row.UsedBy}}{{if $i}}, {{end}}{{$r}}{{end}} {{if eq (len .Row.UsedBy) 1}}uses{{else}}use{{end}} it</label>{{end}}
{{template "password" .}}<div class="actions">{{if .Row.HasValue}}<button class="ghost">Delete value only</button>{{end}}<button class="danger" name="remove_services" value="yes">Remove completely</button></div></form>
</details>
{{template "bottom"}}{{end}}

{{define "error"}}{{template "top" .}}<p class="error">{{.Error}}</p><p><a href="/keys">Back to keys</a></p>{{template "bottom"}}{{end}}

{{define "access"}}{{template "top" .}}
{{with .Notice}}<p class="notice">{{.}}</p>{{end}}
{{with .Error}}<p class="error">{{.}}</p>{{end}}
{{if .Requests}}<h2 class="section" id="requests">Waiting for you</h2>
{{range .Requests}}<form method="post" action="/requests/{{.ID}}" class="card request"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<p class="reqtitle">{{if .Fingerprint}}New agent <b>{{.Role}}</b>{{else}}More access for <b>{{.Role}}</b>{{end}}</p>
{{if .Services}}<p>Full access to {{range $i, $s := .Services}}{{if $i}}, {{end}}<span class="chip">{{$s}}</span>{{end}}</p>{{end}}
{{if .Projects}}<p>Full access to the whole project{{if gt (len .Projects) 1}}s{{end}} {{range $i, $p := .Projects}}{{if $i}}, {{end}}<a class="chip" href="/projects/{{$p}}">{{$p}}</a>{{end}}, services added later included</p>
<p class="hint">To give less, decline and use "Give an agent access" on the project page instead.</p>{{end}}
{{with .Note}}<p class="mute">“{{.}}”</p>{{end}}
<p class="hint">Asked from {{.From}}, {{.Filed.Format "2 Jan 15:04"}} UTC</p>
{{if .Fingerprint}}<p class="hint">Token fingerprint <code class="fp">{{.Fingerprint}}</code></p>{{end}}
{{template "password" $}}
<div class="actions"><button name="answer" value="approve">Approve</button><button class="ghost" name="answer" value="decline">Decline</button></div>
</form>{{end}}{{end}}
<div class="bar"><h1>Agents <span class="count">{{len .Rows}}</span></h1><a class="btn" href="/new/agent">Add agent</a></div>
{{template "projectfilters" .ProjectFilters}}
<div class="tablewrap"><table class="t">
{{template "thead" .Columns}}
<tbody>{{range .Rows}}<tr>
<td class="first"><a class="kname" href="/agents/{{.Role}}">{{.Role}}</a>{{if .Ended}} <span class="pill warn">ended</span>{{end}}</td>
<td class="chips">{{range .Chips}}<a class="chip {{if .Full}}full{{else if .Ended}}ended{{else}}lim{{end}}" href="/access/{{.Role}}/{{.Service}}" title="{{if .Full}}full access{{else}}{{.Label}}{{end}} · {{.Detail}}{{with .Via}} · through project {{.}}{{end}}">{{.Service}}</a>{{end}}{{if .More}}<a class="chip more" href="/agents/{{.Role}}">+{{.More}} more</a>{{end}}{{if not .Cells}}<span class="mute">no APIs yet</span>{{end}}</td>
<td class="num">{{len .Cells}}</td>
<td class="num">{{.CallsToday}}</td>
<td>{{with .LastCall}}{{.}}{{else}}<span class="mute">never</span>{{end}}</td>
<td class="mute">{{with .Ends}}{{.}}{{else}}never{{end}}</td>
<td class="act"><a href="/agents/{{.Role}}">Edit access</a></td>
</tr>{{else}}<tr><td colspan="7" class="empty">No agents yet. Add one, then give it APIs.</td></tr>{{end}}</tbody>
</table></div>
<p class="hint"><span class="chip full">green</span> full access · <span class="chip lim">amber</span> limited (methods, paths, daily limit or end date) · click an API to change it.</p>
{{template "bottom"}}{{end}}

{{define "cell"}}{{template "top" .}}
<div class="head"><a class="back" href="/agents/{{.Form.Role}}">{{.Form.Role}}</a><h1>{{.Form.Service}}</h1></div>
<div class="card">
{{with .Error}}<p class="error">{{.}}</p>{{end}}
{{with .Via}}<p class="hint">{{$.Form.Role}} can already use this service through its grant for the whole project <a href="/projects/{{.}}">{{.}}</a>, with the limits shown below. Saving here makes a grant for this service only, which then applies instead of the project grant. Switching it off here does not take the access away; remove the project grant on the project page.</p>{{end}}
<form method="post" action="/access/{{.Form.Role}}/{{.Form.Service}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="switch"><input type="checkbox" name="on" value="yes"{{if .Form.On}} checked{{end}}> <span>{{.Form.Role}} may use {{.Form.Service}}</span></label>
<details{{if or (ne .Form.Mode "full") (ne .Form.Paths "/") .Form.Daily .Form.Expires}} open{{end}}><summary>{{if and (eq .Form.Mode "full") (eq .Form.Paths "/") (not .Form.Daily) (not .Form.Expires)}}Full access · Limit access{{else}}Limited access{{end}}</summary>
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
</details>
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
{{if .ProjectGrants}}<p>Whole projects, services added later included: {{range $i, $p := .ProjectGrants}}{{if $i}}, {{end}}<a class="chip" href="/projects/{{$p}}">{{$p}}</a>{{end}}</p>{{end}}
<ul class="grants">{{range .Services}}<li><a class="grant" href="/access/{{$.Role}}/{{.Service}}"><span class="svc">{{.Service}}</span><span class="what">{{.Label}}{{with .Via}} · through project {{.}}{{end}}</span></a></li>{{else}}<li class="mute">None yet.</li>{{end}}</ul>
{{if .Off}}<form method="get" action="/access/{{.Role}}/-" class="add" data-pathpick><select name="service" aria-label="Add a service"><option value="">Add a service…</option>{{range .Off}}<option>{{.}}</option>{{end}}</select><noscript><button class="ghost">Open</button></noscript></form>{{end}}
</div>
<div class="card"><dl><dt>Ends</dt><dd>{{with .Expires}}{{.}}{{else}}never{{end}}</dd><dt>Token file</dt><dd><code>{{.File}}</code></dd></dl></div>
<details class="card"><summary>Make a new token</summary><form method="post" action="/agents/{{.Role}}/token"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="current" value="{{.Current}}">
<p class="mute">Shown once. The old token stops working at once.</p>{{template "password" .}}<div class="actions"><button>Make a new token</button></div></form></details>
<details class="card danger"><summary>Revoke</summary><form method="post" action="/agents/{{.Role}}/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="check"><input type="checkbox" name="confirm" value="yes" required> Remove {{.Role}} and all its access; its calls fail at once</label>
{{template "password" .}}<div class="actions"><button class="danger">Revoke agent</button></div></form></details>
{{template "bottom"}}{{end}}

{{define "service"}}{{template "top" .}}
{{if eq .Notice "saved"}}<p class="notice">Saved. Agents with their own grant for this service keep it.</p>{{end}}
<div class="head"><a class="back" href="/keys/{{.F.Key}}">{{.F.Key}}</a><h1 class="mono">{{.Name}}</h1></div>
<div class="card"><dl>
<dt>Key</dt><dd><a class="chip" href="/keys/{{.F.Key}}">{{.F.Key}}</a></dd>
<dt>Base URL</dt><dd class="mono">{{if .F.Base}}{{.F.Base}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Project</dt><dd>{{with .F.Project}}<a class="chip" href="/projects/{{.}}">{{.}}</a>{{if $.ProjectStopped}} <span class="pill warn">{{$.ProjectStopped}}</span>{{end}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Test request</dt><dd class="mono">{{if .F.TestPath}}{{.TestMethod}} {{.F.TestPath}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Agents</dt><dd>{{range .Agents}}<a class="chip" href="/access/{{.}}/{{$.Name}}">{{.}}</a>{{else}}<span class="mute">none</span>{{end}}</dd>
{{if .F.FixedHeaders}}<dt>Fixed headers</dt><dd class="mono">{{range $k, $v := .F.FixedHeaders}}{{$k}}: {{$v}}<br>{{end}}</dd>{{end}}
{{if .F.ExtraHeaders}}<dt>Extra secret headers</dt><dd class="mono">{{range .F.ExtraHeaders}}{{.}}<br>{{end}}</dd>{{end}}
</dl></div>
{{if .Editable}}
<div class="card"><h2>Edit</h2>
<p class="hint">Changes the settings only. Agents with their own grant for this service keep it, with the same methods, paths and limits. Changing the project changes which whole-project grants reach it: agents with a grant for the old project lose this service, those with one for the new project gain it. The key is sent to the base URL below, so check it.</p>
{{with .EditError}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/services/{{.Name}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Key<select name="key">{{range .Keys}}<option{{if eq . $.F.Key}} selected{{end}}>{{.}}</option>{{end}}</select></label>
<label>Base URL<input name="base" value="{{.F.Base}}" inputmode="url" autocapitalize="none" spellcheck="false"></label>
<label>Key sent as<select name="auth">
<option value="bearer"{{if eq .F.Auth "bearer"}} selected{{end}}>Authorization: Bearer</option>
<option value="header"{{if eq .F.Auth "header"}} selected{{end}}>a header</option>
<option value="query"{{if eq .F.Auth "query"}} selected{{end}}>a query parameter</option></select></label>
<div class="two"><label>Header (if a header)<input name="header" value="{{.F.Header}}" autocapitalize="none"></label>
<label>Parameter (if a query)<input name="param" value="{{.F.Param}}" autocapitalize="none"></label></div>
<label>Test request path (optional; sent with the method shown above, {{.TestMethod}})<input name="test_path" value="{{.F.TestPath}}" autocapitalize="none" spellcheck="false"></label>
<label>Pinned certificate SHA-256 (optional, only for a self-signed https service)<input name="tls_pin_sha256" value="{{.F.TLSPin}}" placeholder="64 hex characters" autocapitalize="none" spellcheck="false"></label>
<label>Project (optional: a client or engagement this service belongs to; lowercase letters, digits and -)<input name="project" value="{{.F.Project}}" placeholder="e.g. noted" autocapitalize="none" spellcheck="false"></label>
<details{{if .F.Pasted}} open{{end}}><summary>Or paste settings from an agent</summary>
<label>JSON like {"base":"https://…","auth":"bearer","test_path":"/…"}<textarea name="pasted" spellcheck="false" autocapitalize="none">{{.F.Pasted}}</textarea></label>
<p class="hint">Replaces every setting above, including the project (include "project" to keep it), and the key stays as chosen. Leave "service" out; a service cannot be renamed here. "extra_headers" (header name to the name of another stored key, for example {"Modal-Secret":"MODAL_PROXY_SECRET"}) replaces the extra secret headers; leave it out to keep them, or use {} to remove them. The test method (shown above) is kept; change a POST test to something else in access.json. Optional fixed_headers sets up to two nonsecret header values, for example {"CF-R2-Jurisdiction":"default"}; without it the fixed headers are removed. Never put credentials here.</p>
</details>
{{template "password" .}}
<div class="actions"><button>Save</button></div>
</form></div>
{{else}}<div class="card"><p class="mute">This is a {{.Kind}} service. It carries settings this form does not show, so it is changed in access.json, not here.</p></div>{{end}}
{{template "bottom"}}{{end}}

{{define "projects"}}{{template "top" .}}
<div class="bar"><h1>Projects <span class="count">{{len .Projects}}</span></h1></div>
{{if .Projects}}<div class="tablewrap"><table class="t"><thead><tr><th>Project</th><th>State</th><th class="num">Services</th><th>Ends</th><th>Keys</th></tr></thead><tbody>
{{range .Projects}}<tr><td class="first"><a class="kname" href="/projects/{{.Name}}">{{.Name}}</a></td>
<td>{{if eq .State "running"}}running{{else}}<span class="pill warn">{{.State}}</span>{{end}}</td>
<td class="num">{{.Services}}</td><td class="mute">{{with .Expires}}{{.}}{{else}}—{{end}}</td><td>{{if .ClientOwned}}client-owned{{else}}<span class="mute">—</span>{{end}}</td></tr>{{end}}
</tbody></table></div>
{{else}}<p class="mute">No projects yet.</p>{{end}}
<p class="hint">A project groups a client's services. Put a service in one on its page (Keys, the key, the service, then Project).</p>
{{template "bottom"}}{{end}}

{{define "project"}}{{template "top" .}}
{{if eq .Notice "saved"}}<p class="notice">Saved.</p>{{else if eq .Notice "revoked"}}<p class="notice">Access removed.</p>{{else if eq .Notice "granted"}}<p class="notice">Access given.</p>{{end}}
{{with .ProjectError}}<p class="error">{{.}}</p>{{end}}
<div class="head"><a class="back" href="/projects">Projects</a><h1 class="mono">{{.Name}}</h1>{{if ne .State "running"}}<span class="pill warn">{{.State}}</span>{{end}}</div>
{{if ne .State "running"}}<p class="hint">Every call to this project's services is refused ({{.State}}). Keys and access are kept.</p>{{end}}
<div class="card"><h2>Services</h2>
{{if .Services}}<div class="tablewrap"><table class="t"><thead><tr><th>Service</th><th>Key</th><th>API</th><th>Last used</th><th class="num">Calls today</th></tr></thead><tbody>
{{range .Services}}<tr><td class="first"><a class="kname" href="/services/{{.Name}}">{{.Name}}</a></td><td><a href="/keys/{{.Key}}">{{.Key}}</a></td><td>{{.Provider}}</td><td>{{with .LastUsed}}{{.}}{{else}}<span class="mute">never</span>{{end}}</td><td class="num">{{.CallsToday}}</td></tr>{{end}}
</tbody></table></div>{{else}}<p class="mute">No services. Its settings are kept until you clear them.</p>{{end}}</div>
<div class="card"><h2>Agents with access</h2>
{{range .Agents}}<form method="post" action="/projects/{{$.Name}}/revoke" class="grantrow"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="role" value="{{.Role}}">
<p><a class="chip" href="/agents/{{.Role}}">{{.Role}}</a> {{if .Whole}}whole project, services added later included{{if .Services}}: {{end}}{{end}}{{range $i, $s := .Services}}{{if $i}}, {{end}}{{$s}}{{end}}</p>
<details><summary>Remove {{.Role}}'s access to this project</summary><p class="hint">Removes its access to this project's services{{if .Whole}} and its grant for the whole project{{end}}. Its access to other services stays.</p>{{template "password" $}}<div class="actions"><button class="danger">Remove access</button></div></details></form>
{{else}}<p class="mute">No agent has access to this project.</p>{{end}}</div>
{{if .Roles}}<details class="card"><summary>Give an agent access to this project</summary>
<form method="post" action="/projects/{{.Name}}/grant"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Agent<select name="role">{{range .Roles}}<option>{{.}}</option>{{end}}</select></label>
<p class="lbl">Allowed</p>
<div class="seg" role="radiogroup" aria-label="Allowed methods">
<label><input type="radio" name="mode" value="read"><span>Read only</span></label>
<label><input type="radio" name="mode" value="full" checked><span>Full</span></label>
<label><input type="radio" name="mode" value="custom"><span>Custom</span></label>
</div>
<div class="methods">{{range .AllMethods}}<label class="check"><input type="checkbox" name="method" value="{{.}}"> {{.}}</label>{{end}}</div>
<label>Allowed paths, one per line<textarea name="paths" spellcheck="false" autocapitalize="none">/</textarea></label>
<div class="two"><label>Daily limit, per service<input name="daily" inputmode="numeric" placeholder="none"></label>
<label>Ends on (UTC)<input type="date" name="expires"></label></div>
<label class="check"><input type="checkbox" name="later" value="yes"> Include services added to this project later</label>
<p class="hint">Without the tick, the agent gets these limits on each of the project's {{len .Services}} current service(s), and a service added later needs its own grant. With it, one grant covers the whole project as it changes. A grant for a single service on the agent's page takes precedence.</p>
{{template "password" .}}<div class="actions"><button>Give access</button></div></form></details>{{end}}
<div class="card"><h2>Settings</h2>
<form method="post" action="/projects/{{.Name}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="check"><input type="checkbox" name="paused" value="yes"{{if .P.Paused}} checked{{end}}> Paused: refuse every call to this project's services</label>
<label>Ends (optional; from the start of this day, UTC, the project counts as paused)<input type="date" name="expires" value="{{.ExpiresDate}}"></label>
<label class="check"><input type="checkbox" name="client_owned" value="yes"{{if .P.ClientOwned}} checked{{end}}> Keys belong to the client (shows the handover list)</label>
{{template "password" .}}<div class="actions"><button>Save</button></div></form></div>
{{if .P.ClientOwned}}<div class="card"><h2>Handover: keys to rotate when the engagement ends</h2>
{{if .Handover}}<div class="tablewrap"><table class="t"><thead><tr><th>Key</th><th>Added here</th><th>Last replaced</th></tr></thead><tbody>
{{range .Handover}}<tr><td class="first"><a class="kname" href="/keys/{{.Name}}">{{.Name}}</a>{{if not .HasValue}} <span class="mute">no value</span>{{end}}</td><td>{{.Created}}</td><td>{{.Replaced}}</td></tr>{{end}}
</tbody></table></div>{{else}}<p class="mute">No keys.</p>{{end}}
<p class="hint">Ask the client to rotate each key, then replace or delete it here. Values are never shown. "unknown" means the key was added before the dashboard kept that date.</p></div>{{end}}
{{template "bottom"}}{{end}}
`))
