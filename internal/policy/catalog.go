package policy

import (
	"slices"
	"strings"
	"time"
)

// Service discovery for agents (owner, 2026-11-22): an agent can list and
// search the services, and a wrong name gets "did you mean". Names, providers
// and kinds only; never a key, key name or setting that holds one.

// ServiceVisible reports whether role may learn that the named service exists.
// role is nil for a caller without a role token (a new agent filing a
// request). A service in a client-owned project is shown only to roles whose
// grant for it has not expired at now; every other service to everyone.
func (a AccessList) ServiceVisible(role *Role, name string, now time.Time) bool {
	svc, ok := a.Services[name]
	if !ok {
		return false
	}
	if svc.Project == "" || !a.Projects[svc.Project].ClientOwned {
		return true
	}
	if role == nil {
		return false
	}
	acc, granted := a.AccessFor(*role, name)
	return granted && !acc.Expired(now)
}

// Provider is the host a service calls ("" for a service that calls nothing,
// such as a signing service).
func (s Service) Provider() string {
	if s.base == nil {
		return ""
	}
	return s.base.Hostname()
}

// serviceWords is what a search matches: the name, the provider host, the
// project and the kind of service, lowercased.
func serviceWords(name string, s Service) string {
	return strings.ToLower(name + " " + s.Provider() + " " + s.Project + " " + s.Auth)
}

// queryWords splits a query into its words: letters and digits, at least 3
// long ("ai" alone would match "mail" and "gmail"), unless every word is
// shorter, then all of them.
func queryWords(q string) []string {
	all := strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	var long []string
	for _, w := range all {
		if len(w) >= 3 {
			long = append(long, w)
		}
	}
	if len(long) > 0 {
		return long
	}
	return all
}

// SearchServices returns the services role may see that match query, best
// first: by how many of the query's words they contain, then by name. An
// empty query returns every visible service, by name.
func (a AccessList) SearchServices(role *Role, query string, now time.Time) []string {
	words := queryWords(query)
	type hit struct {
		name  string
		score int
	}
	var hits []hit
	for name, svc := range a.Services {
		if !a.ServiceVisible(role, name, now) {
			continue
		}
		score := 0
		if len(words) > 0 {
			hay := serviceWords(name, svc)
			for _, w := range words {
				if strings.Contains(hay, w) {
					score++
				}
			}
			if score == 0 {
				continue
			}
		}
		hits = append(hits, hit{name, score})
	}
	slices.SortFunc(hits, func(x, y hit) int {
		if x.score != y.score {
			return y.score - x.score
		}
		return strings.Compare(x.name, y.name)
	})
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.name
	}
	return out
}

// DidYouMean is the hint added to an "unknown service" answer: up to three
// visible services sharing a word with name, best first; "" when none.
func (a AccessList) DidYouMean(role *Role, name string, now time.Time) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	similar := a.SearchServices(role, name, now)
	if len(similar) > 3 {
		similar = similar[:3]
	}
	if len(similar) == 0 {
		return ""
	}
	return " (did you mean " + strings.Join(similar, ", ") + "?)"
}
