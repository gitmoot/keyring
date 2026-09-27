package dashboard

import (
	"sort"
	"strconv"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
)

// preset is a known API: how its key is sent and a harmless request that
// shows whether a key works. Connecting a key to a preset needs no typing.
type preset struct {
	ID, Label, Base, Auth, Header, Param, TestPath string
}

var presets = []preset{
	{ID: "anthropic", Label: "Anthropic", Base: "https://api.anthropic.com", Auth: policy.AuthHeader, Header: "x-api-key"},
	{ID: "apify", Label: "Apify", Base: "https://api.apify.com", Auth: policy.AuthBearer, TestPath: "/v2/users/me"},
	{ID: "appfigures", Label: "Appfigures", Base: "https://api.appfigures.com", Auth: policy.AuthBearer, TestPath: "/v2/"},
	{ID: "cloudflare", Label: "Cloudflare", Base: "https://api.cloudflare.com", Auth: policy.AuthBearer, TestPath: "/client/v4/user/tokens/verify"},
	{ID: "dodo", Label: "Dodo Payments", Base: "https://live.dodopayments.com", Auth: policy.AuthBearer, TestPath: "/products"},
	{ID: "e2b", Label: "E2B", Base: "https://api.e2b.app", Auth: policy.AuthHeader, Header: "X-API-Key", TestPath: "/sandboxes"},
	{ID: "elevenlabs", Label: "ElevenLabs", Base: "https://api.elevenlabs.io", Auth: policy.AuthHeader, Header: "xi-api-key", TestPath: "/v1/models"},
	{ID: "github", Label: "GitHub", Base: "https://api.github.com", Auth: policy.AuthBearer, TestPath: "/user"},
	{ID: "groq", Label: "Groq", Base: "https://api.groq.com", Auth: policy.AuthBearer, TestPath: "/openai/v1/models"},
	{ID: "openai", Label: "OpenAI", Base: "https://api.openai.com", Auth: policy.AuthBearer, TestPath: "/v1/models"},
	{ID: "openrouter", Label: "OpenRouter", Base: "https://openrouter.ai", Auth: policy.AuthBearer, TestPath: "/api/v1/key"},
	{ID: "outscraper", Label: "Outscraper", Base: "https://api.app.outscraper.com", Auth: policy.AuthHeader, Header: "X-API-KEY", TestPath: "/requests"},
	{ID: "pexels", Label: "Pexels", Base: "https://api.pexels.com", Auth: policy.AuthHeader, Header: "Authorization", TestPath: "/v1/curated?per_page=1"},
	{ID: "posthog", Label: "PostHog (EU)", Base: "https://eu.posthog.com", Auth: policy.AuthBearer, TestPath: "/api/users/@me"},
	{ID: "resend", Label: "Resend", Base: "https://api.resend.com", Auth: policy.AuthBearer, TestPath: "/domains"},
	{ID: "revenuecat", Label: "RevenueCat", Base: "https://api.revenuecat.com", Auth: policy.AuthBearer, TestPath: "/v2/projects"},
	{ID: "tavily", Label: "Tavily", Base: "https://api.tavily.com", Auth: policy.AuthBearer, TestPath: "/usage"},
	{ID: "whatsapp", Label: "WhatsApp (Meta Graph)", Base: "https://graph.facebook.com", Auth: policy.AuthBearer, TestPath: "/v21.0/me"},
}

func presetByID(id string) (preset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return p, true
		}
	}
	return preset{}, false
}

// suggestPreset guesses the API from a key's name: OPENROUTER_API_KEY is
// OpenRouter, REVENUECAT_SECRET_KEY_MARTIAN is RevenueCat, vCF_TOKEN and
// CF_TOKEN are Cloudflare. "" when nothing matches.
func suggestPreset(keyName string) string {
	words := strings.FieldsFunc(strings.ToLower(keyName), func(r rune) bool { return r == '_' || r == '-' })
	for _, w := range words {
		switch w {
		case "cf", "vcf":
			return "cloudflare"
		case "wa":
			return "whatsapp"
		case "dodo":
			return "dodo"
		}
		for _, p := range presets {
			if w == p.ID {
				return p.ID
			}
		}
	}
	return ""
}

// serviceName proposes a service name for a key connected to preset id:
// the preset's name, or with a suffix from the key when that is taken
// (REVENUECAT_SECRET_KEY_MARTIAN -> revenuecat-martian).
func serviceName(id, keyName string, taken map[string]policy.Service) string {
	if _, used := taken[id]; !used {
		return id
	}
	var extra []string
	for _, w := range strings.FieldsFunc(strings.ToLower(keyName), func(r rune) bool { return r == '_' }) {
		switch w {
		case id, "api", "key", "token", "secret", "access":
			continue
		}
		extra = append(extra, w)
	}
	for i := 0; ; i++ {
		name := id
		if len(extra) > 0 {
			name += "-" + strings.Join(extra, "-")
		}
		if i > 0 {
			name += "-" + strconv.Itoa(i+1)
		}
		if _, used := taken[name]; !used {
			return name
		}
	}
}

// presetOptions lists presets for a select, sorted by label.
func presetOptions() []preset {
	out := append([]preset(nil), presets...)
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}
