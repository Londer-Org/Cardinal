package agent

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"go.londer.be/cardinal/internal/host/machine"
	"go.londer.be/cardinal/internal/host/sudoers"
	"go.londer.be/cardinal/internal/host/userdb"
)

// DefaultConfigPath is where the package puts the agent's configuration.
//
// A file rather than flags in the unit, because the alternative is an operator
// editing a systemd unit — which then conflicts on every package upgrade, and
// which nobody expects to hold deployment settings.
const DefaultConfigPath = "/etc/cardinal/agent.toml"

// Config is what a host needs to know to run the agent.
//
// Everything except Server has a working default, so the smallest file that
// does anything is one line. That matters: a configuration format where the
// minimum viable file is thirty lines is one people copy from a blog post
// without reading.
type Config struct {
	// Server is the base URL of the Cardinal this host belongs to.
	Server string `toml:"server"`

	// Interval is how often to refresh. Not a security boundary — SSH access is
	// decided at certificate issuance — so this trades staleness against load.
	Interval Duration `toml:"interval"`

	KeyPath   string `toml:"key_path"`
	CachePath string `toml:"cache_path"`

	// POSIX serves identity to nss-systemd. Empty SocketDir disables it.
	SocketDir string `toml:"socket_dir"`

	// SudoersPath is the drop-in to render. Empty disables sudoers rendering
	// entirely, which is what a host wants if its sudo rules are managed by
	// configuration management and Cardinal is only there for identity.
	SudoersPath string `toml:"sudoers_path"`

	// HostKeyPath is the machine's own SSH host key. Empty disables host
	// certificate renewal.
	HostKeyPath    string `toml:"host_key_path"`
	HostCertPath   string `toml:"host_cert_path"`
	SSHDConfigPath string `toml:"sshd_config_path"`
}

// Duration is a TOML-friendly time.Duration.
//
// Written out because `interval = "5m"` is what somebody expects to type and
// toml has no duration type. The alternative is `interval_seconds = 300`, which
// is the kind of field that gets set to 300000 by accident.
type Duration time.Duration

// UnmarshalText parses a Go duration string, so a config file can say "15m"
// rather than a count of nanoseconds nobody can read.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("agent: %q is not a duration (try \"5m\"): %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

// LoadConfig reads a configuration file and applies defaults.
//
// A missing file is an error rather than an empty config, because the one
// setting with no sensible default is the server address — and an agent
// silently doing nothing is worse than one that will not start.
func LoadConfig(path string) (*Config, error) {
	c := Config{
		Interval:       Duration(DefaultInterval),
		KeyPath:        machine.DefaultKeyPath,
		CachePath:      DefaultCachePath,
		SocketDir:      userdb.DefaultRunDir,
		SudoersPath:    sudoers.DefaultPath,
		HostKeyPath:    DefaultHostKeyPath,
		HostCertPath:   DefaultHostCertPath,
		SSHDConfigPath: DefaultSSHDDropIn,
	}

	if _, err := toml.DecodeFile(path, &c); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"agent: %s does not exist — the agent needs at least a line "+
					"reading: server = \"https://id.example\"", path)
		}
		return nil, fmt.Errorf("agent: reading %s: %w", path, err)
	}

	if c.Server == "" {
		return nil, fmt.Errorf("agent: %s sets no server address", path)
	}
	return &c, nil
}
