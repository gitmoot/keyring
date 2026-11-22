package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/relay"
	"github.com/gitmoot/keyring/internal/server"
)

// listServices prints the services an agent can find (owner, 2026-11-22).
// With role, it asks through the relay, which adds the role's token, so the
// answer says what the role may use; without one it asks the keyring
// directly, like keyring request, and lists what any agent may ask for.
func listServices(relayURL, upstream, role, search string, asJSON bool, stdout io.Writer) error {
	var target string
	switch {
	case role != "":
		if !policy.ValidRoleName(role) {
			return fmt.Errorf("%q is not a role name", role)
		}
		u, err := relay.CheckUpstream(relayURL)
		if err != nil {
			return err
		}
		target = strings.TrimSuffix(u.String(), "/") + "/" + role + server.ServicesPath
	case upstream != "":
		u, err := relay.CheckUpstream(upstream)
		if err != nil {
			return err
		}
		target = strings.TrimSuffix(u.String(), "/") + server.ServicesPath
	default:
		return errors.New("give --role NAME (through the relay) or --upstream URL (a new agent)")
	}
	if search != "" {
		target += "?search=" + url.QueryEscape(search)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const limit = 4 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("reading the keyring's answer: %w", err)
	}
	if len(raw) > limit {
		return fmt.Errorf("the keyring's answer is over %d MiB; narrow it with --search", limit>>20)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keyring answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var answer struct {
		Services []server.ServiceEntry `json:"services"`
		Ask      string                `json:"ask"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return fmt.Errorf("keyring answered something that is not a service list: %v", err)
	}
	if asJSON {
		_, err := stdout.Write(raw)
		return err
	}
	if len(answer.Services) == 0 {
		if search != "" {
			fmt.Fprintf(stdout, "no service matches %q; run without --search to see them all\n", search)
		} else {
			fmt.Fprintln(stdout, "no services")
		}
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tPROVIDER\tKIND\tPROJECT\tACCESS\tCALL")
	for _, s := range answer.Services {
		access := "-"
		if role != "" {
			access = "not granted"
			if s.Granted {
				access = strings.Join(s.Methods, ",") + " " + strings.Join(s.Paths, ",")
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, dash(s.Provider), s.Kind, dash(s.Project), access, dash(s.Call))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if answer.Ask != "" {
		fmt.Fprintln(stdout, "\n"+strings.ToUpper(answer.Ask[:1])+answer.Ask[1:])
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
