package capability

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// type that represents a Linux capability.
type Cap uint

// constants that match the Linux kernel capabilities.
const (
	CAP_CHOWN            Cap = 0
	CAP_DAC_OVERRIDE     Cap = 1
	CAP_DAC_READ_SEARCH  Cap = 2
	CAP_FOWNER           Cap = 3
	CAP_FSETID           Cap = 4
	CAP_KILL             Cap = 5
	CAP_SETGID           Cap = 6
	CAP_SETUID           Cap = 7
	CAP_SETPCAP          Cap = 8
	CAP_LINUX_IMMUTABLE  Cap = 9
	CAP_NET_BIND_SERVICE Cap = 10
	CAP_NET_BROADCAST    Cap = 11
	CAP_NET_ADMIN        Cap = 12
	CAP_NET_RAW          Cap = 13
	CAP_IPC_LOCK         Cap = 14
	CAP_IPC_OWNER        Cap = 15
	CAP_SYS_MODULE       Cap = 16
	CAP_SYS_RAWIO        Cap = 17
	CAP_SYS_CHROOT       Cap = 18
	CAP_SYS_PTRACE       Cap = 19
	CAP_SYS_PACCT        Cap = 20
	CAP_SYS_ADMIN        Cap = 21
	CAP_SYS_BOOT         Cap = 22
	CAP_SYS_NICE         Cap = 23
	CAP_SYS_RESOURCE     Cap = 24
	CAP_SYS_TIME         Cap = 25
	CAP_SYS_TTY_CONFIG   Cap = 26
	CAP_MKNOD            Cap = 27
	CAP_LEASE            Cap = 28
	CAP_AUDIT_WRITE      Cap = 29
	CAP_AUDIT_CONTROL    Cap = 30
	CAP_SETFCAP          Cap = 31
	CAP_MAC_OVERRIDE     Cap = 32
	CAP_MAC_ADMIN        Cap = 33
	CAP_SYSLOG           Cap = 34
	CAP_WAKE_ALARM       Cap = 35
	CAP_BLOCK_SUSPEND    Cap = 36
	CAP_AUDIT_READ       Cap = 37
)

// caps represents a set of capabilities for a process.
const (
	CAPS   = 1
	BOUNDS = 2
)

// struct that holds a process's capabilities.
type Capabilities struct {
	pid  int
	caps map[Cap]struct{}
}

// creates a new Capabilities instance for a given process ID.
func NewPid(pid int) (*Capabilities, error) {
	return &Capabilities{
		pid:  pid,
		caps: make(map[Cap]struct{}),
	}, nil
}

// clears specific capabilities from the current capability set.
func (c *Capabilities) Unset(mask int, caps ...Cap) {
	for _, cap := range caps {
		delete(c.caps, cap)
	}
}

// applies the current set of capabilities to the process.
func (c *Capabilities) Apply(mask int) error {
	for cap := range c.caps {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			return fmt.Errorf("failed to drop capability %v: %w", cap, err)
		}
	}
	return nil
}
