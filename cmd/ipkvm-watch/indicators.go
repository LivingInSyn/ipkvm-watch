package main

import (
	"os"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Network NetworkConfig          `yaml:"network"`
	HTTP    HTTPConfig             `yaml:"http"`
	USB     map[string][]USBDevice `yaml:"usb"`
}

func GetConfig(path string) *Config {
	c := &Config{}
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		log.Error().Err(err).Msg("ReadFile: %v")
		return nil
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatal().Err(err).Msg("Unmarshal failed")
	}

	return c
}

// --- Network Section ---

// NetworkConfig holds all network-related configurations.
type NetworkConfig struct {
	MDNS         map[string][]string       `yaml:"mdns"`
	MACAddresses map[string]MACPrefixGroup `yaml:"mac_addresses"`
}

// MDNSConfig maps KVM names to a list of mDNS entries.
// type MDNSConfig map[string][]string `yaml:",inline"`

// MACAddressConfig maps KVM names to their MAC address prefix configurations.
// type MACAddressConfig map[string]MACPrefixGroup `yaml:",inline"`

// MACPrefixGroup holds a list of MAC address prefixes for a specific KVM.
type MACPrefixGroup struct {
	Prefixes []MACPrefixEntry `yaml:"prefixes"`
}

// MACPrefixEntry defines a single MAC address prefix rule.
type MACPrefixEntry struct {
	Prefix     string `yaml:"prefix"`
	Confidence string `yaml:"confidence"`
	Reference  string `yaml:"reference,omitempty"` // omitempty for optional fields
}

// --- HTTP Section ---

// HTTPConfig holds all HTTP-related configurations.
type HTTPConfig struct {
	SSL     map[string]string   `yaml:"ssl"`
	Favicon map[string][]string `yaml:"favicon"`
	Title   map[string][]string `yaml:"title"`
}

// SSLConfig maps KVM names to their SSL string.
// type SSLConfig map[string]string `yaml:",inline"`

// FaviconConfig maps KVM names to a list of integer favicons.
// type FaviconConfig map[string][]int `yaml:",inline"`

// TitleConfig maps KVM names to a list of string titles.
// type TitleConfig map[string][]string `yaml:",inline"`

// --- USB Section ---

// USBConfig maps KVM names to a list of USB device configurations.
// type USBConfig map[string][]USBDevice `yaml:",inline"`

// USBDevice defines the configuration for a specific USB device.
type USBDevice struct {
	VID                 string `yaml:"vid"`
	PID                 string `yaml:"pid"`
	Serial              string `yaml:"serial"`
	Manufacturer        string `yaml:"manufacturer"`
	WindowsSearchString string `yaml:"windows_search_sring"`
}
