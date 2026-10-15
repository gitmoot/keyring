//go:build linux || darwin

package server

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// Kill the entire command group on timeout, including a gcloud Python child.
func boundGoogleCommand(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = kill
	return func() { _ = kill() }, nil
}
