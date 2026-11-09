package admin

import (
	"regexp"
	"strings"
	"testing"
)

// Owner rule (2026-10-15): no decorative colour on cards, rows or panels: no
// coloured side stripe, no tinted background per status, no coloured border
// per status. Status is a neutral pill with one small dot (a ::before or .dot);
// only buttons may be filled with a status colour (the danger button).
func TestCSSHasNoColouredStripesOrTints(t *testing.T) {
	stripe := regexp.MustCompile(`border-left(-color)?\s*:|inset\s+-?[1-9]\d*px\s+0`)
	status := regexp.MustCompile(`var\(--(ok|bad|warn)(-bg)?\)`)
	fill := regexp.MustCompile(`(^|;)\s*background(-color)?\s*:[^;]*var\(--(ok|bad|warn)`)
	border := regexp.MustCompile(`(^|;)\s*(border|border-color|outline|box-shadow)\s*:[^;]*var\(--(ok|bad|warn)`)
	if m := regexp.MustCompile(`--(ok|bad|warn)-bg`).FindString(css); m != "" {
		t.Errorf("status tint variable %s", m)
	}
	for _, rule := range strings.Split(css, "}") {
		selector, body, ok := strings.Cut(rule, "{")
		if !ok {
			continue
		}
		selector = strings.TrimSpace(selector[strings.LastIndex(selector, "{")+1:])
		if stripe.MatchString(body) {
			t.Errorf("%s: coloured side stripe: %s", selector, body)
		}
		if !status.MatchString(body) {
			continue
		}
		if border.MatchString(body) {
			t.Errorf("%s: status-coloured border: %s", selector, body)
		}
		dot := strings.Contains(selector, "::before") || strings.Contains(selector, ".dot")
		button := strings.HasPrefix(selector, "button.")
		if fill.MatchString(body) && !dot && !button {
			t.Errorf("%s: status-coloured background: %s", selector, body)
		}
	}
}
