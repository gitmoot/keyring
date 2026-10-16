package gcloudexec

import "bytes"

// ReauthDiagnosis contains only fixed SDK/OAuth evidence, never command output.
type ReauthDiagnosis struct {
	Required      bool
	InvalidRAPT   bool
	RAPTRequired  bool
	PromptRefused bool
}

// ClassifyReauth accepts transient lowercased stderr. Host renewal and container
// login must agree: an auth URL, bearer token or generic sign-in advice alone is
// not evidence that Google requires reauthentication.
func ClassifyReauth(lower []byte) ReauthDiagnosis {
	has := func(text string) bool { return bytes.Contains(lower, []byte(text)) }
	d := ReauthDiagnosis{
		PromptRefused: has("cannot prompt during non-interactive execution") || has("cannot prompt during noninteractive execution"),
		InvalidRAPT:   has("reauth related error (invalid_rapt)") || has("'error_subtype': 'invalid_rapt'") || has("\"error_subtype\": \"invalid_rapt\"") || has("\"error_subtype\":\"invalid_rapt\""),
		RAPTRequired:  has("'error_subtype': 'rapt_required'") || has("\"error_subtype\": \"rapt_required\"") || has("\"error_subtype\":\"rapt_required\""),
	}
	d.Required = d.InvalidRAPT || d.RAPTRequired || has(": reauth is required.") || has(") reauth is required.") || bytes.Equal(bytes.TrimSpace(lower), []byte("reauth is required.")) || (has("please run:") && has("gcloud auth login") && has("to complete reauthentication.")) || (d.PromptRefused && (has("reauthentication failed.") || has("problem reauthenticating while refreshing")))
	return d
}
