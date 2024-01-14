package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// CvemapConfig represents Cvemap configuration dir env var.
const CvemapConfig = "CVEMAPCONFIG"

var (
	//CvemapConfigFile represents config file location.
	CvemapConfigFile = filepath.Join(CvemapHome(), "config.yml")
)

type Config struct {
	Cvemap *Cvemap `yaml:"cvemap"`
}

// CvemapHome returns Cvemap configs home directory.
func CvemapHome() string {
	if env := os.Getenv(CvemapConfig); env != "" {
		//log.Debug().Msg("env CL: " + env)
		return env
	}
	xdgCLHome, err := xdg.ConfigFile("cvemap")
	//log.Debug().Msg("xdgsclhome: " + xdgCLHome)

	if err != nil {
		gologger.Fatal().Msgf(err.Error(), "Unable to create configuration directory for cvemap")
	}

	return xdgCLHome
}

// Load cvemap configuration from file.
func (c *Config) Load(path string) error {
	f, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c.Cvemap = NewCvemap()

	var cfg Config
	if err := yaml.Unmarshal(f, &cfg); err != nil {
		return err
	}
	if cfg.Cvemap != nil {
		c.Cvemap = cfg.Cvemap
	}
	return nil
}

// Save configuration to disk.
func (c *Config) Save() error {
	//c.Validate()

	return c.SaveFile(CvemapConfigFile)
}

// SaveFile K9s configuration to disk.
func (c *Config) SaveFile(path string) error {
	EnsurePath(path, DefaultDirMod)
	cfg, err := yaml.Marshal(c)
	if err != nil {
		gologger.Error().Msgf("[Config] Unable to save cvemap config file: %v", err)
		return err
	}
	gologger.Info().Msg(fmt.Sprintf("Config Path: %v", path))
	return os.WriteFile(path, cfg, 0644)
}
