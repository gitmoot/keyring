//go:build !linux && !darwin

package server

import (
	"errors"
	"os/exec"
)

func boundGoogleCommand(cmd *exec.Cmd) (func(), error) {
	return nil, errors.New("gcloud credentials require a Linux or macOS keyring host")
}
