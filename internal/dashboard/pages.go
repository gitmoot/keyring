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
<a href="/activity" class="nav{{if eq .Page "activity"}} on{{end}}">Activity</a>
<a href="/access#requests" class="nav">Requests<span class="n{{if .PendingCount}} hot{{end}}">{{.PendingCount}}</span></a>
</nav>
{{with .Nav.ProjectList}}<p class="sec">Projects</p><nav class="sidenav projects" aria-label="Projects">{{range .}}<a href="/projects/{{.Name}}" class="nav"><i class="dot {{.Dot}}"></i>{{.Name}}<span class="n">{{.Services}}</span></a>{{end}}</nav>{{end}}
<div class="me">{{with .Nav.Version}}<span class="ver">{{.}}</span>{{end}}<form method="post" action="/logout" class="logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="link">Log out</button></form></div>
</aside>
<main class="body{{if or (eq .Page "keys") (eq .Page "access")}} wide{{end}}">{{end}}
{{define "bottom"}}</main></body></html>{{end}}

{{define "password"}}<label class="pw">Dashboard password<input type="password" name="password" autocomplete="current-password" required placeholder="asked on every change"></label>{{end}}

{{define "bitcoinfields"}}<label>Network<select name="network" data-btcnetwork data-testpaths="{{.Test.Taproot}}" data-mainnetpaths="{{.Main.Taproot}}">{{range .Networks}}<option{{if .On}} selected{{end}}>{{.Value}}</option>{{end}}</select></label>
<p class="warnbox" data-mainnetnotice{{if not .Mainnet}} hidden{{end}}>Mainnet signs real bitcoin. It needs an xprv or mainnet WIF key of its own (not a test network service's), signs only for {{template "pathlist" .Main.TaprootList}} (optionally {{template "pathlist" .Main.SegWit}}) and only with sighash default and all, and needs notify_command in the rules file: every signature runs it. Every agent's grant needs both sats limits, at most {{.MaxTx}} per PSBT and {{.MaxDay}} per day, typed out to confirm; a fee over {{.MaxFee}} sats or {{.MaxFeeRate}} sat/vB is refused.</p>
{{if .WIF}}<label>Script (a WIF key signs for one address)<select name="script">{{range .Scripts}}<option{{if .On}} selected{{end}}>{{.Value}}</option>{{end}}</select></label>
<p class="hint">p2tr: taproot key path (BIP86 style). p2wpkh: native SegWit.</p>
{{else}}<label>Paths it signs for, one per line<textarea name="paths" spellcheck="false" autocapitalize="none">{{.Paths}}</textarea></label>
<p class="hint">Taproot (BIP86) receive and change. For native SegWit (BIP84) add {{template "segwithint" .Test}}{{template "segwithint" .Main}}. A trailing /* means any index; hardened steps take ' or h.</p>{{end}}
<p class="hint">Sighash types it signs:</p>
{{range .Sighash}}<label class="check"><input type="checkbox" name="sighash" value="{{.Value}}"{{if .On}} checked{{end}}> <span class="mono">{{.Value}}</span></label>{{end}}
<p class="hint">default and all commit to the whole transaction. With none, single or an |anyonecanpay form the other side may change what the signature does not cover, so the sats a PSBT sends are only what it sends now. Tick them only if your tool needs them; mainnet refuses them.</p>{{end}}
{{define "segwithint"}}<span data-segwithint="{{.Side}}"{{if .Hidden}} hidden{{end}}>{{range $i, $p := .SegWit}}{{if $i}} and {{end}}<span class="mono">{{$p}}</span>{{end}}</span>{{end}}
{{define "pathlist"}}{{range $i, $p := .}}{{if $i}} and {{end}}{{$p}}{{end}}{{end}}

{{define "thead"}}<thead><tr>{{range .}}<th{{with .Class}} class="{{.}}"{{end}}>{{if .Href}}<a href="{{.Href}}">{{.Label}}{{with .Arrow}} <span class="arrow">{{.}}</span>{{end}}</a>{{else}}{{.Label}}{{end}}</th>{{end}}</tr></thead>{{end}}

{{define "status"}}<span class="pill {{.StatusClass}}">{{.Status}}</span>{{end}}

{{define "projectfilters"}}{{if .}}<nav class="filters" aria-label="Project">{{range .}}<a class="f{{if .On}} on{{end}}" href="{{.Href}}">{{.Label}}{{if ge .Count 0}} <b>{{.Count}}</b>{{end}}</a>{{end}}</nav>{{end}}{{end}}
{{define "keys"}}{{template "top" .}}
{{if eq .Notice "deleted"}}<p class="notice">Key deleted.</p>{{end}}
<div class="bar"><h1>Keys <span class="count">{{len .Rows}}</span></h1>
<form method="get" action="/keys" class="tsearch">{{with .Project}}<input type="hidden" name="project" value="{{.}}">{{end}}{{with .Show}}<input type="hidden" name="show" value="{{.}}">{{end}}{{with .Sort}}<input type="hidden" name="sort" value="{{.}}">{{end}}{{if .Desc}}<input type="hidden" name="desc" value="1">{{end}}<input type="search" name="q" value="{{.Query}}" placeholder="Search keys or APIs" aria-label="Search"></form>
<a class="btn ghost" href="/new/key#upload">Upload key file</a><a class="btn" href="/new/key">Add key</a></div>
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
<div id="value-rows"><div class="vrow" data-row><div class="vline"><label>Value<input type="password" name="value" autocomplete="off" placeholder="paste it here; it is never shown again"></label>
<button type="button" class="ghost" data-removerow aria-label="Remove this value" hidden>×</button></div>
<details class="more"><summary>Label or name</summary><div class="two"><label>Label (optional)<input name="label" maxlength="80" placeholder="e.g. Jerry's Max account" autocomplete="off"></label>
<label>Value name (optional)<input name="part" pattern="[a-z0-9_]{1,32}" placeholder="e.g. id; empty: numbered" autocapitalize="none" autocomplete="off" spellcheck="false"></label></div></details></div></div>
<div class="actions addrow"><button type="button" class="ghost" data-addrow="value-rows" data-max="{{.MaxParts}}" aria-label="Add another value" hidden>+ Add value</button></div>
<p class="hint">Paste the key. Use + for a key with several values (they are tried in order).</p>
<noscript><p class="hint">Without JavaScript one value is added here; add more on the key's page under Add a value.</p></noscript>
{{template "password" .}}
<div class="actions"><button>Add key</button><a class="btn ghost" href="/keys">Cancel</a></div>
</form></div>
<p class="hint">Just the name and the value or values. Which API it is for can be set on the key's page, now or later.</p>
<div class="card" id="upload"><h2>Upload a key file</h2>
<p class="hint">For a key that comes as a file, such as an Apple .p8 or a .pem private key. The file is checked before it is stored: a file without a usable private key is refused. It is stored like <code>keyring set --file</code> and never shown again.</p>
{{with .UploadError}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/new/key/upload" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name<input name="name" value="{{.UploadName}}" required pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="TANDEM_APNS_KEY" autocapitalize="characters" autocomplete="off" spellcheck="false"></label>
<label>Key file<input type="file" name="file" required accept=".p8,.pem,.key,.txt"></label>
<label class="check"><input type="checkbox" name="replace" value="yes"> Replace the key if this name exists</label>
{{template "password" .}}
<div class="actions"><button>Upload</button></div>
</form></div>
{{template "bottom"}}{{end}}

{{define "key"}}{{template "top" .}}
{{if eq .Notice "uploaded"}}<p class="notice">Key file stored{{with .Meta.Kind}}: {{.}}{{end}}{{with .Meta.Fingerprint}}, fingerprint {{.}}{{end}}. Connect it to a service below.</p>{{else if eq .Notice "added"}}<p class="notice">Key added.</p>{{else if eq .Notice "connected"}}<p class="notice">Connected. Give agents access under Agents.</p>{{else if eq .Notice "renamed"}}<p class="notice">Key renamed. Services that used it now use the new name.</p>{{else if eq .Notice "value-added"}}<p class="notice">Value added, last in the list.</p>{{else if eq .Notice "value-labelled"}}<p class="notice">Label saved.</p>{{else if eq .Notice "value-moved"}}<p class="notice">Order saved. A key pool tries the values in this order.</p>{{else if eq .Notice "value-renamed"}}<p class="notice">Value renamed. Services that used it now use the new name.</p>{{else if eq .Notice "value-removed"}}<p class="notice">Value removed.</p>{{else if .Notice}}<p class="notice">Key {{.Notice}}.</p>{{end}}
{{if eq .Error "password"}}<p class="error">Enter your dashboard password to do that.</p>{{else if eq .Error "part"}}<p class="error">Pick the value to replace.</p>{{else if eq .Error "value"}}<p class="error">Paste the new value, on one line.</p>{{else if eq .Error "value-control"}}<p class="error">The value has a line break or control character inside it, so it was not saved. Paste only the key itself.</p>{{else if eq .Error "in-use"}}<p class="error">Agents still use this key. Tick the box to delete it anyway.</p>{{else if eq .Error "no-test"}}<p class="error">No service using this key has a test request.</p>{{else if eq .Error "no-value"}}<p class="error">This key has no stored value.</p>{{else if eq .Error "changed"}}<p class="error">The key's values or the service changed during the test, so its result was not kept. Run it again.</p>{{end}}
{{with .EditError}}<p class="error">{{.}}</p>{{end}}
{{if eq .Error "never-shown"}}<p class="error">A Bitcoin key is never shown, not even here. Keep your own backup of it.</p>{{end}}
<div class="head"><a class="back" href="/keys">Keys</a><h1 class="mono">{{.Row.Name}}</h1>{{template "status" .Row}}</div>
<div class="card"><dl>
{{if .Row.Parts}}<dt>Values</dt><dd>{{range .Row.Parts}}<span class="chip mono">{{.Name}}</span>{{with .Label}} · {{.}}{{end}} {{if .HasValue}}<span class="masked">••••••••</span>{{else}}<span class="mute">none stored</span>{{end}}{{if .Pooled}} <span class="pill {{.PoolClass}}">{{.PoolStatus}}</span> <span class="mute">{{.CallsToday}} today · {{.CallsWeek}} in 7 days{{if .FailuresToday}} · {{.FailuresToday}} refused today{{end}}{{with .LastUsed}} · last {{.}}{{end}}</span>{{end}}<br>{{end}}<span class="mute">never shown</span>{{if and (gt (len .Row.Parts) 0) (index .Row.Parts 0).Pooled}}<br><span class="hint">Key pool: each call uses the first value in this list that is not set aside; a value the provider refuses (bad key, no credit, rate limit) is set aside for a while and the call goes out again with the next.</span>{{end}}</dd>
{{else}}<dt>Value</dt><dd>{{if .Row.HasValue}}<span class="masked">••••••••</span>{{with .Row.Label}} · {{.}}{{end}} <span class="mute">never shown</span>{{else}}none stored{{end}}</dd>{{end}}
{{with .Meta.Kind}}<dt>File</dt><dd>{{.}}{{with $.Meta.Fingerprint}} · <code>{{.}}</code>{{end}}</dd>{{end}}
{{with .Bitcoin}}<dt>Bitcoin key</dt><dd>{{.Kind}} · {{.Networks}}{{with .Fingerprint}} · fingerprint <code>{{.}}</code>{{end}} · <span class="mute">never shown</span></dd>{{end}}
<dt>Services</dt><dd>{{range .Row.Services}}<a class="chip" href="/services/{{.}}">{{.}}</a>{{else}}<span class="mute">not connected yet</span>{{end}}</dd>
<dt>Agents</dt><dd>{{range .Row.UsedBy}}<a class="chip" href="/agents/{{.}}">{{.}}</a>{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Last used</dt><dd>{{with .Row.LastUsed}}{{.}}{{else}}never{{end}} · {{.Row.CallsToday}} today</dd>
{{if not .Meta.CheckedAt.IsZero}}<dt>Tested</dt><dd>{{.Meta.CheckedAt.Format "2006-01-02 15:04"}} UTC</dd>{{end}}
</dl>
{{if and .Row.AnyValue (not .NeverShown)}}<details class="inline"><summary>Show {{if .Row.Parts}}values{{else}}value{{end}}</summary><form method="post" action="/keys/{{.Row.Name}}/reveal"><input type="hidden" name="csrf" value="{{.CSRF}}">{{template "password" .}}<div class="actions"><button class="ghost">Show</button></div></form></details>{{end}}
{{if .Testable}}<form method="post" action="/keys/{{.Row.Name}}/test" class="inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Test now</button></form>{{end}}
</div>

<details class="card"{{if or (not .Row.Services) .ConnectError}} open{{end}}><summary>{{if .Row.Services}}Connect to another service{{else}}Connect to a service{{end}}</summary>
{{with .ConnectError}}<p class="error">{{.}}</p>{{end}}
{{if .BitcoinForm}}<form method="post" action="/keys/{{.Row.Name}}/connect"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="auth" value="bitcoin-psbt-sign">{{with .BitcoinKeyPart}}<input type="hidden" name="key_part" value="{{.}}">{{end}}
<p class="hint">A Bitcoin signing service: an agent sends a PSBT and gets it back with this key's inputs signed. The key never leaves keyring and is never shown.</p>
<label>Service name<input name="service" value="{{.Connect.Service}}" placeholder="e.g. btc-ord" autocapitalize="none" spellcheck="false"></label>
{{template "bitcoinfields" .BitcoinForm}}
<details><summary>Or paste settings</summary>
<label>JSON like {"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest",{{if .BitcoinForm.WIF}}"script":"p2tr"{{else}}"paths":["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*"]{{end}}}}<textarea name="pasted" spellcheck="false" autocapitalize="none"></textarea></label>
<p class="hint">The service as access.json writes it works too: {"btc-ord":{"auth":"bitcoin-psbt-sign","key":"{{.Row.Name}}{{with .BitcoinKeyPart}}.{{.}}{{end}}","bitcoin":{…}}}. A "key" in it must be {{.Row.Name}}{{with .BitcoinKeyPart}}.{{.}}{{end}}. Pasted settings replace the fields above.</p>
</details>
{{template "password" .}}
<div class="actions"><button>Connect</button></div>
</form>{{else}}
<form method="get" action="/keys/{{.Row.Name}}" class="presetpick"><label>Which API?<select name="preset" data-autosubmit>
<option value=""{{if eq .Connect.Preset ""}} selected{{end}}>Other (fill in below)</option>
{{range .Presets}}<option value="{{.ID}}"{{if eq .ID $.Connect.Preset}} selected{{end}}>{{.Label}}</option>{{end}}
</select></label><noscript><button class="ghost">Use</button></noscript></form>
<form method="post" action="/keys/{{.Row.Name}}/connect"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="preset" value="{{.Connect.Preset}}">
<details{{if .ConnectError}} open{{end}}><summary>Settings{{if .Connect.Preset}}: {{.Connect.Base}}{{end}}</summary>
<label>Service name<input name="service" value="{{.Connect.Service}}" placeholder="e.g. openrouter" autocapitalize="none" spellcheck="false"></label>
<label>Base URL<input name="base" value="{{.Connect.Base}}" placeholder="e.g. https://api.example.com" inputmode="url" autocapitalize="none" spellcheck="false"></label>
<label>Key sent as<select name="auth">
<option value="bearer"{{if eq .Connect.Auth "bearer"}} selected{{end}}>Authorization: Bearer</option>
<option value="header"{{if eq .Connect.Auth "header"}} selected{{end}}>a header</option>
<option value="query"{{if eq .Connect.Auth "query"}} selected{{end}}>a query parameter</option></select></label>
<label>Scheme (if not Bearer)<input name="scheme" value="{{.Connect.Scheme}}" placeholder="e.g. Key" autocapitalize="none" spellcheck="false"></label>
<div class="two"><label>Header (if a header)<input name="header" value="{{.Connect.Header}}" placeholder="e.g. X-Api-Key" autocapitalize="none"></label>
<label>Parameter (if a query)<input name="param" value="{{.Connect.Param}}" placeholder="e.g. api_key" autocapitalize="none"></label></div>
<label>Test request (optional, a harmless GET)<input name="test_path" value="{{.Connect.TestPath}}" placeholder="e.g. /v1/models" autocapitalize="none" spellcheck="false"></label>
<label>Pinned certificate SHA-256 (optional, only for a self-signed https service)<input name="tls_pin_sha256" value="{{.Connect.TLSPin}}" placeholder="64 hex characters" autocapitalize="none" spellcheck="false"></label>
{{if .Row.Parts}}<label>Value sent as the key<select name="key_part">{{range .Row.Parts}}<option{{if eq .Name $.Connect.KeyPart}} selected{{end}}>{{.Name}}</option>{{end}}</select></label>
<p class="hint">Send the other values as extra headers (optional):</p>
<div class="two">{{range .Row.Parts}}<label>Header for {{.Name}}<input name="part_header_{{.Name}}" placeholder="e.g. Modal-Secret; leave empty if this is the key" autocapitalize="none" spellcheck="false"></label>{{end}}</div>{{end}}
</details>
{{if eq .Meta.Kind "EC P-256 private key"}}<details open><summary>Or paste settings{{if .Row.Services}}{{else}}: Apple keys{{end}}</summary>
<p class="hint">For an Apple key, paste one of these with your IDs from Apple Developer (Key ID from the .p8 file name, Team ID from Membership):<br>
Push notifications: <code>{"service":"apns","base":"https://api.push.apple.com","auth":"apns","apns":{"key_id":"KEY_ID","team_id":"TEAM_ID"}}</code><br>
Sign in with Apple: <code>{"service":"NAME","auth":"sign-in-with-apple-sign","sign_in_with_apple":{"client_id":"BUNDLE_ID","team_id":"TEAM_ID","key_id":"KEY_ID"}}</code></p>{{else}}<details><summary>Or paste settings from an agent</summary>{{end}}
<label>JSON like {"service":"x","base":"https://…","auth":"bearer","test_path":"/…"}<textarea name="pasted" spellcheck="false" autocapitalize="none"></textarea></label>
{{if .Row.Parts}}<p class="hint">For a key pool over all these values, in list order: {"service":"x","base":"https://…","auth":"header","header":"x-api-key","key_pool":true} (no key_part). For one value as the key, add "key_part" and name the others in extra_headers by their value name: {"service":"modal-ocr","base":"https://…","auth":"header","header":"Modal-Key","key_part":"{{(index .Row.Parts 0).Name}}"{{if gt (len .Row.Parts) 1}},"extra_headers":{"Modal-Secret":"{{(index .Row.Parts 1).Name}}"}{{end}}}</p>{{end}}
<p class="hint">For an API that needs a second secret, either give one key several values, or add it as its own key first, then name it in extra_headers: {"Modal-Secret":"MODAL_PROXY_SECRET"} (header name to key name, never a value; up to two). Optional fixed_headers sets up to two nonsecret header values, for example {"CF-R2-Jurisdiction":"default"}. These override caller values and are not redacted from responses. Never put credentials here.</p>
</details>
{{template "password" .}}
<div class="actions"><button>Connect</button></div>
</form>{{end}}</details>

<div class="card" id="add-value"><h2>Add a value</h2>
<p class="hint">It goes last in the list. Without a name it gets the next number{{if not .Row.Parts}}; this key's value becomes value 1 and services using {{.Row.Name}} change to {{.Row.Name}}.1{{end}}.</p>
<form method="post" action="/keys/{{.Row.Name}}/add-value"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Value<input type="password" name="value" autocomplete="off" required></label>
<details class="more"><summary>Label or name</summary><div class="two"><label>Label (optional)<input name="label" maxlength="80" placeholder="e.g. Jerry's Max account" autocomplete="off"></label>
<label>Value name (optional)<input name="part" pattern="[a-z0-9_]{1,32}" placeholder="empty: numbered" autocapitalize="none" autocomplete="off" spellcheck="false"></label></div></details>
{{template "password" .}}<div class="actions"><button class="ghost">Add value</button></div></form></div>

{{if .Row.Parts}}<details class="card" id="values"><summary>Order and labels</summary>
<form method="post" action="/keys/{{.Row.Name}}/move-up"><input type="hidden" name="csrf" value="{{.CSRF}}">
<p class="hint">A key pool tries the values in this order.</p>
{{range $i, $p := .Row.Parts}}<p><span class="chip mono">{{.Name}}</span>{{with .Label}} · {{.}}{{end}}{{if $i}} <button class="ghost" name="part" value="{{.Name}}">Move up</button>{{end}}</p>{{end}}
{{template "password" .}}</form>
<hr>{{end}}
{{if or .Row.Parts .Row.HasValue}}{{if not .Row.Parts}}<details class="card" id="values"><summary>Label</summary>{{end}}
<form method="post" action="/keys/{{.Row.Name}}/label"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Row.Parts}}<div class="two"><label>Value<select name="part">{{range .Row.Parts}}<option value="{{.Name}}">{{.Name}}{{with .Label}} · {{.}}{{end}}</option>{{end}}</select></label>{{else}}<input type="hidden" name="part" value="">{{end}}
<label>Label<input name="label" maxlength="80" placeholder="empty: no label" autocomplete="off"{{if not .Row.Parts}} value="{{.Row.Label}}"{{end}}></label>{{if .Row.Parts}}</div>{{end}}
{{template "password" .}}<div class="actions"><button class="ghost">Save label</button></div></form>
<p class="hint">A label is for you only: it is not secret and does not change which value is sent.</p>
</details>{{end}}

<div class="card"><h2>Replace {{if .Row.Parts}}a value{{else}}value{{end}}</h2><form method="post" action="/keys/{{.Row.Name}}/replace"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Row.Parts}}<label>Which value<select name="part">{{range .Row.Parts}}<option value="{{.Name}}">{{.Name}}{{with .Label}} · {{.}}{{end}}</option>{{end}}</select></label>{{end}}
<label>New value<input type="password" name="value" autocomplete="off" required></label>{{template "password" .}}<div class="actions"><button>Replace</button></div></form></div>

<details class="card" id="rename"><summary>Rename {{if .Row.Parts}}the key or a value{{else}}the key{{end}}</summary>
<form method="post" action="/keys/{{.Row.Name}}/rename"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>New key name<input name="new_name" value="{{.Row.Name}}" required pattern="[A-Za-z_][A-Za-z0-9_]*" autocapitalize="characters" autocomplete="off" spellcheck="false"></label>
{{template "password" .}}<div class="actions"><button class="ghost">Rename key</button></div></form>
{{if .Row.Parts}}<hr><form method="post" action="/keys/{{.Row.Name}}/rename-value"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="two"><label>Value<select name="part">{{range .Row.Parts}}<option>{{.Name}}</option>{{end}}</select></label>
<label>New value name<input name="new_part" required pattern="[a-z0-9_]{1,32}" autocapitalize="none" autocomplete="off" spellcheck="false"></label></div>
{{template "password" .}}<div class="actions"><button class="ghost">Rename value</button></div></form>{{end}}
<p class="hint">Services that use the key or value are changed to the new name; agents keep their access. A key pool's counts and set-aside state for renamed values start over.</p>
</details>

<details class="card danger"><summary>Leaked or no longer needed</summary>
<form method="post" action="/keys/{{.Row.Name}}/leaked"><input type="hidden" name="csrf" value="{{.CSRF}}"><p class="mute">Marking it leaked shows a warning until you replace it.</p>{{template "password" .}}<div class="actions"><button class="ghost">Mark as leaked</button></div></form>
{{if .Row.Parts}}<hr>
<form method="post" action="/keys/{{.Row.Name}}/remove-value"><input type="hidden" name="csrf" value="{{.CSRF}}">
<p>Remove one value. A value a service names (its key or an extra header) is kept; a key pool's values can go (the pool stops using them).</p>
<label>Value<select name="part">{{range .Row.Parts}}{{if .HasValue}}<option value="{{.Name}}">{{.Name}}{{with .Label}} · {{.}}{{end}}</option>{{end}}{{end}}</select></label>
{{template "password" .}}<div class="actions"><button class="ghost">Remove value</button></div></form>{{end}}
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
{{range .Services}}{{if index $.Mainnet .}}<p class="warnbox"><b>{{.}}</b> signs real bitcoin on mainnet: set its sats limits (at most {{$.MainnetMaxTx}} per PSBT, {{$.MainnetMaxDay}} per day), then type its name and the daily limit to confirm.</p>
<div class="two"><label>{{.}}: max sats per PSBT<input name="max_sats_tx.{{.}}" inputmode="numeric" autocomplete="off"></label><label>{{.}}: max sats per day (UTC)<input name="max_sats_day.{{.}}" inputmode="numeric" autocomplete="off"></label></div>
<div class="two"><label>Type the service name<input name="confirm_service.{{.}}" autocomplete="off" spellcheck="false" autocapitalize="none"></label><label>Type the daily limit<input name="confirm_daily.{{.}}" inputmode="numeric" autocomplete="off"></label></div>{{end}}{{end}}
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
<details{{if or .Mainnet (ne .Form.Mode "full") (ne .Form.Paths "/") .Form.Daily .Form.Expires .Form.MaxSatsTx .Form.MaxSatsDay}} open{{end}}><summary>{{if and (eq .Form.Mode "full") (eq .Form.Paths "/") (not .Form.Daily) (not .Form.Expires) (not .Form.MaxSatsTx) (not .Form.MaxSatsDay)}}Full access · Limit access{{else}}Limited access{{end}}</summary>
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
{{if .Bitcoin}}{{if .Mainnet}}<p class="warnbox">Mainnet: real bitcoin. Both sats limits are required: at most {{.MainnetMaxTx}} per PSBT and {{.MainnetMaxDay}} per day, the first no more than the second.</p>{{end}}
<div class="two"><label>Max sats per PSBT<input name="max_sats_tx" inputmode="numeric" value="{{.Form.MaxSatsTx}}" placeholder="{{if .Mainnet}}required{{else}}none{{end}}"></label>
<label>Max sats per day (UTC)<input name="max_sats_day" inputmode="numeric" value="{{.Form.MaxSatsDay}}" placeholder="{{if .Mainnet}}required{{else}}none{{end}}"></label></div>
<p class="hint">Counted per signed PSBT: outputs that do not pay back to this key, plus the fee. Paths: /sign-psbt signs, /addresses lists addresses.</p>{{end}}
</details>
{{if .Mainnet}}<p class="hint">To give this grant or raise a limit, also type the service name and the daily limit. Lowering a limit or switching the grant off needs only the password.</p>
<div class="two"><label>Type the service name<input name="confirm_service" autocomplete="off" spellcheck="false" autocapitalize="none"></label>
<label>Type the daily limit<input name="confirm_daily" inputmode="numeric" autocomplete="off"></label></div>{{end}}
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

{{define "reveal"}}{{template "top" .}}
<div class="head"><a class="back" href="/keys/{{.Name}}">{{.Name}}</a><h1 class="mono">{{.Name}}</h1></div>
<div class="card">
<p class="warnbox">Shown because you asked. Copy what you need and leave this page; it is not kept, and the audit log records that it was shown.</p>
{{range .Values}}<label>{{.Label}}{{if .Multiline}}<textarea id="{{.ID}}" data-exact="{{.Exact}}" readonly autocomplete="off" spellcheck="false" rows="8">
{{.Value}}</textarea>{{else}}<input id="{{.ID}}" data-exact="{{.Exact}}" readonly autocomplete="off" spellcheck="false" value="{{.Value}}">{{end}}</label>{{with .Warning}}<p class="warnbox">This value {{.}}.</p>{{end}}<div class="actions"><button type="button" data-copy="{{.ID}}">Copy {{.Label}}</button></div>{{end}}
<div class="actions"><a class="btn ghost" href="/keys/{{.Name}}">Done</a></div></div>
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
<div class="card"><h2>Activity log</h2>{{if .AuditSaved}}<p class="notice">Saved.</p>{{end}}
<p>{{if .AuditRead}}{{.Role}} may search the audit log: every agent's calls (time, service, path, status) and dashboard events, never key values.{{else}}{{.Role}} may not search the audit log.{{end}}</p>
<form method="post" action="/agents/{{.Role}}/audit"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="allow" value="{{if .AuditRead}}no{{else}}yes{{end}}">
{{template "password" .}}<div class="actions"><button{{if .AuditRead}} class="ghost"{{end}}>{{if .AuditRead}}Stop audit access{{else}}Allow audit search{{end}}</button></div></form>
<p class="hint">Through its relay: <code>GET /{{.Role}}/_keyring/audit?from=2026-11-15T16:39&amp;to=2026-11-15T16:39&amp;service=&amp;role=&amp;path=</code>, the same search as the Activity page.</p></div>
<div class="card"><dl><dt>Ends</dt><dd>{{with .Expires}}{{.}}{{else}}never{{end}}</dd><dt>Token file</dt><dd><code>{{.File}}</code></dd></dl></div>
<details class="card"><summary>Make a new token</summary><form method="post" action="/agents/{{.Role}}/token"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="current" value="{{.Current}}">
<p class="mute">Shown once. The old token stops working at once.</p>{{template "password" .}}<div class="actions"><button>Make a new token</button></div></form></details>
<details class="card danger"><summary>Revoke</summary><form method="post" action="/agents/{{.Role}}/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label class="check"><input type="checkbox" name="confirm" value="yes" required> Remove {{.Role}} and all its access; its calls fail at once</label>
{{template "password" .}}<div class="actions"><button class="danger">Revoke agent</button></div></form></details>
{{template "bottom"}}{{end}}

{{define "service"}}{{template "top" .}}
{{if eq .Notice "saved"}}<p class="notice">Saved. Agents with their own grant for this service keep it.</p>{{end}}
<div class="head"><a class="back" href="/keys/{{.F.Key}}">{{.F.Key}}</a><h1 class="mono">{{.Name}}</h1>{{with .Bitcoin}}<span class="pill{{if eq .Network "mainnet"}} warn{{end}}">{{.Network}}{{if eq .Network "mainnet"}} · real bitcoin{{end}}</span>{{end}}</div>
{{if .Mainnet}}<p class="warnbox">This service signs real bitcoin on mainnet. Every grant has both sats limits (at most {{.MainnetMaxTx}} per PSBT and {{.MainnetMaxDay}} per day); a PSBT with a fee over {{.MainnetMaxFee}} sats or {{.MainnetMaxFeeRate}} sat/vB is refused; every signature is listed below and sent to notify_command.</p>{{end}}
<div class="card"><dl>
<dt>Key</dt><dd><a class="chip" href="/keys/{{.F.Key}}">{{.F.Key}}</a></dd>
{{with .SentAs}}<dt>Sent as</dt><dd class="mono">Authorization: {{.}} …</dd>{{end}}
<dt>Base URL</dt><dd class="mono">{{if .F.Base}}{{.F.Base}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Project</dt><dd>{{with .F.Project}}<a class="chip" href="/projects/{{.}}">{{.}}</a>{{if $.ProjectStopped}} <span class="pill warn">{{$.ProjectStopped}}</span>{{end}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Test request</dt><dd class="mono">{{if .F.TestPath}}{{.TestMethod}} {{.F.TestPath}}{{else}}<span class="mute">none</span>{{end}}</dd>
<dt>Agents</dt><dd>{{range .Agents}}<a class="chip" href="/access/{{.}}/{{$.Name}}">{{.}}</a>{{else}}<span class="mute">none</span>{{end}}</dd>
{{if .F.FixedHeaders}}<dt>Fixed headers</dt><dd class="mono">{{range $k, $v := .F.FixedHeaders}}{{$k}}: {{$v}}<br>{{end}}</dd>{{end}}
{{with .OAuth2}}<dt>OAuth client ID</dt><dd class="mono">{{.ClientID}}</dd><dt>Token URL</dt><dd class="mono">{{.TokenURL}}</dd>{{if .ClientSecretKey}}<dt>Client secret</dt><dd class="mono">{{.ClientSecretKey}}{{if not $.SecretStored}} <span class="mute">(no value stored)</span>{{end}}</dd>{{end}}{{with .Scopes}}<dt>Scopes</dt><dd class="mono">{{range .}}{{.}}<br>{{end}}</dd>{{end}}{{end}}
{{if .F.KeyPool}}<dt>Key pool</dt><dd>every value of <span class="mono">{{.F.Key}}</span>, in the key's list order; each value's state and use are on the <a href="/keys/{{.F.KeyBase}}">key's page</a></dd>{{end}}
{{if .F.ForwardRole}}<dt>Agent name</dt><dd>sent as <span class="mono">X-Keyring-Role</span></dd>{{end}}
{{if .F.ExtraHeaders}}<dt>Extra secret headers</dt><dd class="mono">{{range .F.ExtraHeaders}}{{.}}<br>{{end}}</dd>{{end}}
{{with .Bitcoin}}<dt>Network</dt><dd>{{.Network}}{{if eq .Network "mainnet"}} (real bitcoin){{else}} (test network){{end}}</dd>
<dt>Signs for</dt><dd class="mono">{{range .Paths}}{{.}}<br>{{end}}{{with .Script}}{{.}} (one WIF key){{end}}</dd>
<dt>Sighash</dt><dd class="mono">{{if .Sighash}}{{range .Sighash}}{{.}} {{end}}{{else}}default all{{end}}</dd>
<dt>Calls</dt><dd class="mono">POST /_keyring/bitcoin/{{$.Name}}/sign-psbt<br>GET /_keyring/bitcoin/{{$.Name}}/addresses?path=…</dd>{{end}}
{{with .BitcoinKeyError}}<dt>Bitcoin key</dt><dd><span class="pill warn">cannot sign</span> {{.}}</dd>{{end}}
{{with .BitcoinFingerprint}}<dt>Fingerprint</dt><dd class="mono">{{.}} <span class="mute">key never shown</span></dd>{{end}}
</dl></div>
{{if .BitcoinWatch}}<div class="card"><h2>Watch-only</h2>
<div class="tablewrap"><table class="t"><thead><tr><th>Path</th><th>Descriptor</th><th>First address</th></tr></thead><tbody>
{{range .BitcoinWatch}}<tr><td class="mono">{{.Path}}</td><td class="mono">{{.Descriptor}}</td><td class="mono">{{.FirstAddress}}</td></tr>{{end}}
</tbody></table></div>
<p class="hint">Public keys only: import a descriptor watch-only to check addresses and balances.</p></div>{{end}}
{{if eq .Kind "bitcoin-psbt-sign"}}<div class="card"><h2>Signatures</h2>
{{with .SignaturesError}}<p class="error">{{.}}</p>{{end}}
{{if .Signatures}}<div class="tablewrap"><table class="t"><thead><tr><th>Time (UTC)</th><th>Agent</th><th>Network</th><th>Txid</th><th>Inputs</th><th class="num">External sats</th><th class="num">Fee sats</th><th class="num">Fee rate</th><th>Status</th></tr></thead><tbody>
{{range .Signatures}}<tr><td class="mono">{{.Time}}</td><td>{{.Role}}</td><td>{{.Network}}</td><td class="mono">{{.Txid}}</td><td class="mono">{{range $i, $n := .Inputs}}{{if $i}}, {{end}}{{$n}}{{end}}</td><td class="num">{{.ExternalSats}}</td><td class="num">{{.FeeSats}}</td><td class="num">{{with .FeeRate}}{{.}} sat/vB{{else}}<span class="mute">unknown</span>{{end}}</td><td><span class="pill ok">signed</span></td></tr>{{end}}
</tbody></table></div>
{{else if not .SignaturesError}}<p class="mute">No signatures in the last {{.SignatureDays}} days.</p>{{end}}
<p class="hint">From the audit log, newest first, the last {{.SignatureDays}} days (up to 50). The audit never records a PSBT or a key.</p></div>{{end}}
{{if .Editable}}
<div class="card"><h2>Edit</h2>
<p class="hint">{{if .BitcoinForm}}Changes the signing rules and the project. Agents with their own grant for this service keep it, with the same paths and sats limits. Changing the project changes which whole-project grants reach it: agents with a grant for the old project lose this service, those with one for the new project gain it and may sign with it, without sats limits (a project grant has none; give an agent its own grant for limits). A mainnet service is reached by grants of its own only: a project grant never gives access to it, wherever it moves.{{else}}Changes the settings only. Agents with their own grant for this service keep it, with the same methods, paths and limits. Changing the project changes which whole-project grants reach it: agents with a grant for the old project lose this service, those with one for the new project gain it. The key is sent to the base URL below, so check it.{{end}}</p>
{{with .EditError}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/services/{{.Name}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Key<select name="key">{{range .Keys}}<option{{if eq . $.F.Key}} selected{{end}}>{{.}}</option>{{end}}</select></label>
{{if .BitcoinForm}}<input type="hidden" name="auth" value="bitcoin-psbt-sign">
{{template "bitcoinfields" .BitcoinForm}}
{{else}}<label>Base URL<input name="base" value="{{.F.Base}}" inputmode="url" autocapitalize="none" spellcheck="false"></label>
{{if eq .F.Auth "oauth2"}}<input type="hidden" name="auth" value="oauth2">
<p class="hint">OAuth service: the key is the refresh token. An "invalid_client" from the provider means the client ID or secret below does not match its console.</p>
<label>OAuth client ID<input name="client_id" value="{{.F.ClientID}}" autocapitalize="none" spellcheck="false"></label>
<label>Token URL<input name="token_url" value="{{.F.TokenURL}}" inputmode="url" autocapitalize="none" spellcheck="false"></label>
<label>Client secret (a key)<select name="client_secret_key"><option value=""{{if not .F.ClientSecretKey}} selected{{end}}>none (public client)</option>{{range .Keys}}<option{{if eq . $.F.ClientSecretKey}} selected{{end}}>{{.}}</option>{{end}}</select></label>
{{else}}<label>Key sent as<select name="auth">
<option value="bearer"{{if eq .F.Auth "bearer"}} selected{{end}}>Authorization: Bearer</option>
<option value="header"{{if eq .F.Auth "header"}} selected{{end}}>a header</option>
<option value="query"{{if eq .F.Auth "query"}} selected{{end}}>a query parameter</option></select></label>
<label>Scheme (if not Bearer)<input name="scheme" value="{{.F.Scheme}}" placeholder="e.g. Key" autocapitalize="none" spellcheck="false"></label>
<div class="two"><label>Header (if a header)<input name="header" value="{{.F.Header}}" autocapitalize="none"></label>
<label>Parameter (if a query)<input name="param" value="{{.F.Param}}" autocapitalize="none"></label></div>{{end}}
<label>Test request path (optional; sent with the method shown above, {{.TestMethod}})<input name="test_path" value="{{.F.TestPath}}" autocapitalize="none" spellcheck="false"></label>
<label>Pinned certificate SHA-256 (optional, only for a self-signed https service)<input name="tls_pin_sha256" value="{{.F.TLSPin}}" placeholder="64 hex characters" autocapitalize="none" spellcheck="false"></label>{{end}}
<label>Project (optional: a client or engagement this service belongs to; lowercase letters, digits and -)<input name="project" value="{{.F.Project}}" placeholder="e.g. noted" autocapitalize="none" spellcheck="false"></label>
{{if not .BitcoinForm}}<label class="check"><input type="checkbox" name="forward_role" value="yes"{{if .F.ForwardRole}} checked{{end}}> Tell the service which agent is calling (sends <span class="mono">X-Keyring-Role</span>; for services you run yourself, such as a build server)</label>{{end}}
<details{{if .F.Pasted}} open{{end}}><summary>Or paste settings from an agent</summary>
{{if .BitcoinForm}}<label>JSON like {"auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest",{{if .BitcoinForm.WIF}}"script":"p2tr"{{else}}"paths":["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*"]{{end}}}}<textarea name="pasted" spellcheck="false" autocapitalize="none">{{.F.Pasted}}</textarea></label>
<p class="hint">Replaces the rules above and the project (include "project" to keep it); the key stays as chosen, and a "key" in the settings must be that key. The service as access.json writes it works too: {"{{.Name}}":{"auth":"bitcoin-psbt-sign","key":"{{.F.Key}}","bitcoin":{…}}}.</p>
{{else}}<label>JSON like {"base":"https://…","auth":"bearer","test_path":"/…"}<textarea name="pasted" spellcheck="false" autocapitalize="none">{{.F.Pasted}}</textarea></label>
<p class="hint">Replaces every setting above, including the project (include "project" to keep it), and the key stays as chosen. Leave "service" out; a service cannot be renamed here. "extra_headers" (header name to the name of another stored key, for example {"Modal-Secret":"MODAL_PROXY_SECRET"}) replaces the extra secret headers; leave it out to keep them, or use {} to remove them. The test method (shown above) is kept; change a POST test to something else in access.json. Optional fixed_headers sets up to two nonsecret header values, for example {"CF-R2-Jurisdiction":"default"}; without it the fixed headers are removed. Never put credentials here.</p>{{end}}
</details>
{{template "password" .}}
<div class="actions"><button>Save</button></div>
</form></div>
{{else}}<div class="card"><p class="mute">This is a {{.Kind}} service. It carries settings this form does not show, so it is changed in access.json, not here.</p></div>{{end}}
{{template "bottom"}}{{end}}

{{define "activity"}}{{template "top" .}}
<div class="bar"><h1>Activity</h1></div>
<form method="get" action="/activity" class="card"><div class="two">
<label>From (UTC)<input type="datetime-local" name="from" value="{{.Q.From}}"></label>
<label>To (UTC, minute included)<input type="datetime-local" name="to" value="{{.Q.To}}"></label>
</div><div class="two">
<label>Service<input name="service" value="{{.Q.Service}}" autocapitalize="none" spellcheck="false" placeholder="any"></label>
<label>Agent<input name="role" value="{{.Q.Role}}" autocapitalize="none" spellcheck="false" placeholder="any"></label>
</div>
<label>Path contains<input name="path" value="{{.Q.Path}}" autocapitalize="none" spellcheck="false" placeholder="e.g. /v1/jobs/j_ce4ce15b"></label>
<div class="actions"><button>Show</button></div></form>
{{with .ActivityError}}<p class="error">{{.}}</p>{{end}}
{{if .Rows}}{{if .More}}<p class="hint">Showing the newest {{.Limit}}; narrow the search to see older ones.</p>{{end}}
<div class="tablewrap"><table class="t"><thead><tr><th>Time (UTC)</th><th>Agent</th><th>Service</th><th>Call</th><th class="num">Status</th><th>From</th><th>Note</th></tr></thead><tbody>
{{range .Rows}}<tr><td class="mono">{{.Time}}</td><td>{{if .Admin}}<span class="mute">dashboard</span>{{else}}{{.Role}}{{end}}</td><td>{{.Service}}</td>
<td class="mono">{{if .Admin}}{{.Admin}}{{else}}{{.Method}} {{.Path}}{{end}}</td><td class="num">{{if .Status}}{{.Status}}{{end}}</td><td class="mono mute">{{.Source}}</td><td class="mute">{{.Note}}</td></tr>{{end}}
</tbody></table></div>
{{else if not .ActivityError}}<p class="mute">Nothing in this window.</p>{{end}}
<p class="hint">From the audit log: every call an agent made through the keyring and every dashboard change. Paths are shown without their query string; key values are never recorded.</p>
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
