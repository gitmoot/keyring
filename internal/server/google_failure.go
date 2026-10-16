package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
)

const (
	GoogleCauseHeader    = "X-Keyring-Google-Cause"
	GoogleStageHeader    = "X-Keyring-Google-Stage"
	GoogleRecoveryHeader = "X-Keyring-Google-Recovery"
)

// GoogleFailure contains only allowlisted metadata from one bounded attempt.
// It deliberately has no wrapped error or retained command/response text.
type GoogleFailure struct {
	Category    string   `json:"category"`
	Stage       string   `json:"stage"`
	Evidence    []string `json:"evidence,omitempty"`
	ExitCode    *int     `json:"exit_code,omitempty"`
	TimedOut    bool     `json:"timed_out,omitempty"`
	OutputLimit bool     `json:"output_limit,omitempty"`
	WaitLimit   bool     `json:"wait_limit,omitempty"`
}

func (f *GoogleFailure) Error() string {
	switch f.Category {
	case "reauth_required":
		return "Google requires interactive reauthentication for this account; the owner must sign in on the Keyring host. The reason for that requirement is not established."
	case "credentials_invalid":
		return "Google rejected the credential or its identity/lifetime check; the owner must review this account's credentials before choosing a repair."
	case "permission_denied":
		return "Keyring could not access the Google runtime or private configuration; inspect host permissions, not a new login."
	case "configuration_error":
		return "The private Google configuration is unavailable or unsafe; repair the Keyring host configuration, not a new login."
	case "runtime_unavailable":
		return "The Google command runtime is missing or broken; repair the installed Keyring host runtime, not a new login."
	case "network_error":
		return "Google renewal encountered a connection or TLS failure; inspect connectivity, not a new login."
	case "provider_error":
		return "Google token validation or the provider failed; inspect the provider response category in the protected incident record, not a new login."
	case "timeout":
		return "Google renewal exceeded a time bound; inspect the host/runtime or connectivity at the recorded stage, not a new login."
	case "output_limit":
		return "The Google command exceeded its output bound; inspect the installed host runtime, not a new login."
	default:
		return "Google renewal failed for an unknown reason; inspect Keyring's protected incident record before choosing a repair. Sign-in is not established as the remedy."
	}
}

func (f *GoogleFailure) Recovery() string {
	switch f.Category {
	case "reauth_required":
		return "owner_reauth"
	case "credentials_invalid":
		return "owner_review_credentials"
	case "permission_denied", "configuration_error", "runtime_unavailable", "output_limit":
		return "repair_host"
	case "network_error":
		return "check_connectivity"
	case "provider_error":
		return "inspect_provider"
	case "timeout":
		if f.Stage == "token_validation" {
			return "check_connectivity"
		}
	}
	return "inspect_host"
}

func googleFailure(category, stage string, evidence ...string) *GoogleFailure {
	return &GoogleFailure{Category: category, Stage: stage, Evidence: evidence}
}

func (f *GoogleFailure) valid() bool {
	if f == nil {
		return false
	}
	switch f.Category {
	case "reauth_required", "credentials_invalid", "permission_denied", "configuration_error", "runtime_unavailable", "network_error", "provider_error", "timeout", "output_limit", "unknown":
	default:
		return false
	}
	switch f.Stage {
	case "configuration", "command_start", "command", "token_validation":
	default:
		return false
	}
	if f.ExitCode != nil && (*f.ExitCode < -1 || *f.ExitCode > 255) || len(f.Evidence) > 8 {
		return false
	}
	for _, evidence := range f.Evidence {
		switch evidence {
		case "reauthentication_required", "noninteractive_prompt_refused", "invalid_rapt", "rapt_required", "invalid_grant", "credential_revoked", "permission_denied", "configuration_unavailable", "configuration_not_private", "default_configuration_missing", "runtime_missing", "runtime_start_failed", "python_runtime_broken", "tls_error", "connection_error", "provider_unavailable", "provider_permission_denied", "invalid_token", "identity_mismatch", "expired_access_token", "invalid_token_response", "unusable_token_output", "output_limit", "deadline_exceeded", "process_wait_limit", "unrecognized_command_failure":
		default:
			return false
		}
	}
	return true
}

// classifyGoogleCommand reads only bounded transient stderr. All returned
// strings are constants; unknown output cannot be echoed, logged or retained.
func classifyGoogleCommand(ctx context.Context, err error, stderr []byte, outputLimit bool) *GoogleFailure {
	failure := googleFailure("unknown", "command", "unrecognized_command_failure")
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		code := exited.ExitCode()
		failure.ExitCode = &code
	}
	failure.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	failure.OutputLimit = outputLimit
	failure.WaitLimit = errors.Is(err, exec.ErrWaitDelay)
	switch {
	case outputLimit:
		failure.Category, failure.Evidence = "output_limit", []string{"output_limit"}
		return failure
	case failure.TimedOut:
		failure.Category, failure.Evidence = "timeout", []string{"deadline_exceeded"}
		return failure
	case failure.WaitLimit:
		failure.Category, failure.Evidence = "timeout", []string{"process_wait_limit"}
		return failure
	case os.IsPermission(err):
		failure.Category, failure.Stage, failure.Evidence = "permission_denied", "command_start", []string{"permission_denied"}
		return failure
	case errors.Is(err, exec.ErrNotFound), os.IsNotExist(err):
		failure.Category, failure.Stage, failure.Evidence = "runtime_unavailable", "command_start", []string{"runtime_missing"}
		return failure
	}
	var startError *os.PathError
	if errors.As(err, &startError) {
		failure.Category, failure.Stage, failure.Evidence = "runtime_unavailable", "command_start", []string{"runtime_start_failed"}
		return failure
	}
	if !errors.As(err, &exited) {
		failure.Stage, failure.Evidence = "command_start", []string{"runtime_start_failed"}
	}

	lower := bytes.ToLower(stderr)
	defer clear(lower)
	has := func(text string) bool { return bytes.Contains(lower, []byte(text)) }
	prompt := has("cannot prompt during non-interactive execution") || has("cannot prompt during noninteractive execution")
	// Match SDK/OAuth error evidence, not a code embedded in an auth URL,
	// bearer token or an unrelated advisory to sign in.
	invalidRAPT := has("reauth related error (invalid_rapt)") || has("'error_subtype': 'invalid_rapt'") ||
		has("\"error_subtype\": \"invalid_rapt\"") || has("\"error_subtype\":\"invalid_rapt\"")
	raptRequired := has("'error_subtype': 'rapt_required'") ||
		has("\"error_subtype\": \"rapt_required\"") || has("\"error_subtype\":\"rapt_required\"")
	reauth := has(": reauth is required.") || has(") reauth is required.") ||
		bytes.Equal(bytes.TrimSpace(lower), []byte("reauth is required.")) ||
		(has("please run:") && has("gcloud auth login") && has("to complete reauthentication.")) ||
		(prompt && (has("reauthentication failed.") || has("problem reauthenticating while refreshing")))
	switch {
	case invalidRAPT, raptRequired, reauth:
		failure.Category, failure.Evidence = "reauth_required", []string{"reauthentication_required"}
		if invalidRAPT {
			failure.Evidence = append(failure.Evidence, "invalid_rapt")
		}
		if raptRequired {
			failure.Evidence = append(failure.Evidence, "rapt_required")
		}
		if prompt {
			failure.Evidence = append(failure.Evidence, "noninteractive_prompt_refused")
		}
	case has("'error': 'invalid_grant'"), has("\"error\": \"invalid_grant\""), has("\"error\":\"invalid_grant\""),
		has("'invalid_grant:"), has(" invalid_grant:"), bytes.HasPrefix(lower, []byte("invalid_grant:")):
		failure.Category, failure.Evidence = "credentials_invalid", []string{"invalid_grant"}
	case has("token has been expired or revoked"), has("token has been revoked"):
		failure.Category, failure.Evidence = "credentials_invalid", []string{"credential_revoked"}
	case has("configuration [default] does not exist"), has("configuration 'default' does not exist"), has("configuration default does not exist"):
		failure.Category, failure.Evidence = "configuration_error", []string{"default_configuration_missing"}
	case has("permission_denied"):
		failure.Category, failure.Evidence = "provider_error", []string{"provider_permission_denied"}
	case has("permissionerror:"), has("[errno 13]"), has("permission denied"):
		failure.Category, failure.Evidence = "permission_denied", []string{"permission_denied"}
	case has("modulenotfounderror:"), has("importerror:"), has("bad interpreter:"), has("dyld:"):
		failure.Category, failure.Evidence = "runtime_unavailable", []string{"python_runtime_broken"}
	case failure.ExitCode != nil && *failure.ExitCode == 127 && (has("not found") || has("no such file or directory")):
		failure.Category, failure.Evidence = "runtime_unavailable", []string{"runtime_missing"}
	case has("certificate_verify_failed"), has("sslerror"), has("tls handshake"):
		failure.Category, failure.Evidence = "network_error", []string{"tls_error"}
	case has("connectionerror"), has("connection refused"), has("name resolution"), has("name or service not known"), has("read timed out"), has("connecttimeout"):
		failure.Category, failure.Evidence = "network_error", []string{"connection_error"}
	case has("service unavailable"), has("httperror 503"), has("httperror 502"), has("httperror 500"):
		failure.Category, failure.Evidence = "provider_error", []string{"provider_unavailable"}
	}
	return failure
}

func classifyGoogleValidation(ctx context.Context, err error) *GoogleFailure {
	var network net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		failure := googleFailure("timeout", "token_validation", "deadline_exceeded")
		failure.TimedOut = true
		return failure
	}
	return googleFailure("network_error", "token_validation", "connection_error")
}

func reservedGoogleHeader(name string) bool {
	return strings.EqualFold(name, GoogleCauseHeader) ||
		strings.EqualFold(name, GoogleStageHeader) ||
		strings.EqualFold(name, GoogleRecoveryHeader)
}

func sameGoogleFailure(a, b *GoogleFailure) bool {
	if (a.ExitCode == nil) != (b.ExitCode == nil) || a.ExitCode != nil && *a.ExitCode != *b.ExitCode {
		return false
	}
	return a.Category == b.Category && a.Stage == b.Stage && a.TimedOut == b.TimedOut &&
		a.OutputLimit == b.OutputLimit && a.WaitLimit == b.WaitLimit && slices.Equal(a.Evidence, b.Evidence)
}
