//go:build !linux && !darwin

package gcloudexec

import (
	"errors"
	"os/exec"
)

func Bound(cmd *exec.Cmd) (func(), error) {
	return nil, errors.New("gcloud credentials require a Linux or macOS keyring host")
}
