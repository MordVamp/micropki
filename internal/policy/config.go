package policy

import (
	"os"

	"gopkg.in/yaml.v3"
	"micropki/internal/logger"
)

type Config struct {
	Validity struct {
		RootMaxDays         int `yaml:"root_max_days"`
		IntermediateMaxDays int `yaml:"intermediate_max_days"`
		EndEntityMaxDays    int `yaml:"end_entity_max_days"`
	} `yaml:"validity"`

	Keys struct {
		RSARootMinBits         int `yaml:"rsa_root_min_bits"`
		RSAIntermediateMinBits int `yaml:"rsa_intermediate_min_bits"`
		RSAEndEntityMinBits    int `yaml:"rsa_end_entity_min_bits"`
		ECCCAMinSize           int `yaml:"ecc_ca_min_size"`
		ECCEndEntityMinSize    int `yaml:"ecc_end_entity_min_size"`
	} `yaml:"keys"`
}

var CurrentConfig *Config

func LoadConfig(path string) {
	CurrentConfig = &Config{}
	// Default bounds
	CurrentConfig.Validity.RootMaxDays = 3650
	CurrentConfig.Validity.IntermediateMaxDays = 1825
	CurrentConfig.Validity.EndEntityMaxDays = 365

	CurrentConfig.Keys.RSARootMinBits = 4096
	CurrentConfig.Keys.RSAIntermediateMinBits = 3072
	CurrentConfig.Keys.RSAEndEntityMinBits = 2048
	CurrentConfig.Keys.ECCCAMinSize = 384
	CurrentConfig.Keys.ECCEndEntityMinSize = 256

	if path == "" {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// just use defaults
			return
		}
		logger.Error("Failed to read policy configuration %s: %v", path, err)
		return
	}

	if err := yaml.Unmarshal(data, CurrentConfig); err != nil {
		logger.Error("Failed to parse policy configuration %s: %v", path, err)
	} else {
		logger.Info("Loaded policy configuration from %s", path)
	}
}

func init() {
	LoadConfig("")
}
