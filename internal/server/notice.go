package server

// Signature notices (#187): every mainnet signature sends the owner a notice
// through the channel picked in the rules file (policy.Notify). The gram
// channel POSTs {"text": "..."} with the notice token as a bearer token to a
// relay's notify listener, which runs herdr gram send.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// NoticeTimeout bounds how long the keyring waits for one notice. It is
// longer than the relay's 20-second budget for the gram command, so a slow
// but successful notice is never reported as failed.
const NoticeTimeout = 30 * time.Second

// noticeClient sends notices: no proxy from the environment, no redirects
// (the token goes to the configured URL only).
var noticeClient = &http.Client{
	Transport: &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// SendNotice sends text through notify, with keys holding its token, and
// waits for the answer within NoticeTimeout. The error never holds the
// token.
func SendNotice(ctx context.Context, notify *policy.Notify, keys map[string]string, text string) error {
	if notify == nil {
		return errors.New("no notice channel set")
	}
	token := keys[notify.TokenKey]
	if token == "" {
		return fmt.Errorf("%s is not stored", notify.TokenKey)
	}
	switch notify.Channel {
	case policy.NotifyGram:
	default:
		return fmt.Errorf("channel %q is not supported", notify.Channel)
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, NoticeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notify.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("the notify url is not usable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := noticeClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("no answer within %s", NoticeTimeout)
		}
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return uerr.Err
		}
		return err
	}
	// Only the status matters; the body is not read (no connection is
	// reused), and the peer's reason phrase is not repeated.
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the relay answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// notifyBitcoin sends msg through the rules' notice channel in the
// background: the signature is already answered and never waits for it. A
// notice that fails or gets no answer within NoticeTimeout is written to the
// audit log.
func (h *Handler) notifyBitcoin(notify *policy.Notify, keys map[string]string, role, service, msg string) {
	go func() {
		err := SendNotice(context.Background(), notify, keys, msg)
		if err == nil {
			return
		}
		h.writeAudit(auditRecord{Time: h.now().UTC().Format(time.RFC3339), Source: "keyring", Role: role, Service: service,
			Method: "NOTIFY", Path: "/" + bitcoinSignAction, Note: "signature notice not sent: " + err.Error()})
	}()
}
