package dashboard

import (
	"net/http"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// Signature notices (#187): every mainnet signature sends the owner a notice
// through the channel picked in the rules file ("notify"). The rules file is
// root's, so the Bitcoin service pages show the channel and send a test
// notice; the channel itself is changed in the rules file.

// noticeLabels are the channels' names as the page shows them.
var noticeLabels = map[string]string{policy.NotifyGram: "Gram"}

// noticeView is the notice setting as the page shows it: the token key is
// named, never its value.
type noticeView struct {
	ChannelName, URL, TokenKey string
	TokenStored                bool
}

func noticesOf(n *policy.Notify, keys map[string]string) *noticeView {
	if n == nil {
		return nil
	}
	return &noticeView{ChannelName: noticeLabels[n.Channel], URL: n.URL, TokenKey: n.TokenKey, TokenStored: keys[n.TokenKey] != ""}
}

// noticeChannelNames are the channels the owner can pick.
func noticeChannelNames() []string {
	names := make([]string, len(policy.NotifyChannels))
	for i, c := range policy.NotifyChannels {
		names[i] = noticeLabels[c]
	}
	return names
}

// testNotice sends a test notice through the configured channel, after the
// dashboard password, and shows the outcome on the service page. Both
// outcomes are audited.
func (b *Backend) testNotice(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	cfg := b.Proxy.Config()
	svc, ok := cfg.Services[name]
	if !ok || svc.Auth != policy.AuthBitcoinPSBTSign {
		b.notFound(w, sid)
		return
	}
	f := formOf(name, svc)
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderService(w, sid, http.StatusForbidden, f, "", "", "Enter your dashboard password to send a test notice.")
		return
	}
	if cfg.Notify == nil {
		b.renderService(w, sid, http.StatusConflict, f, "", "", "No signature notice channel is set in the rules file.")
		return
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	err = server.SendNotice(r.Context(), cfg.Notify, keys, "keyring: test signature notice from the dashboard ("+name+")")
	fields := map[string]any{"channel": cfg.Notify.Channel, "service": name, "sent": err == nil}
	if err != nil {
		fields["error"] = err.Error()
	}
	b.Admin.Audit("signature_notice_test", sid, fields)
	if err != nil {
		b.renderService(w, sid, http.StatusBadGateway, f, "", "", "The test notice was not sent: "+err.Error())
		return
	}
	b.renderService(w, sid, http.StatusOK, f, "notice-sent", "", "")
}
