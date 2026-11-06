package server

import (
	"sort"

	"github.com/gitmoot/keyring/internal/policy"
)

// HeaderSafe reports whether value can be sent as an HTTP header value: no
// byte below space except tab, and no DEL (RFC 9110 5.5). Net/http refuses to
// send anything else, and its error says nothing about the key. Spaces, tabs
// and non-ASCII bytes are legal and are not touched.
func HeaderSafe(value string) bool {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// unsendableKey names the store key whose value cannot go in the header the
// service puts it in, or "". Only bearer and header services send the stored
// value in a header as it is; a query key is escaped, and OAuth and Google
// services send a token the provider issued.
func unsendableKey(svc policy.Service, key string, keys map[string]string) string {
	if svc.Auth == policy.AuthBearer || svc.Auth == policy.AuthHeader {
		if !HeaderSafe(key) {
			return svc.Key
		}
	}
	names := make([]string, 0, len(svc.ExtraHeaders))
	for _, name := range svc.ExtraHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !HeaderSafe(keys[name]) {
			return name
		}
	}
	return ""
}
