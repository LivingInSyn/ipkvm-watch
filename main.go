package main

import (
	"slices"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Indicators struct {
}

func main() {
	// This is a placeholder for the main function.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("Starting network discovery")

	// load the indicators.yaml file
	config := GetConfig()

	// perform mdns discovery
	mdns, err := resolveMDNSNames(config.Network.MDNS)
	if err != nil {
		log.Error().Err(err).Msg("mDNS discovery failed")
	} else {
		for _, result := range mdns {
			log.Info().Str("domain", result.Domain).Msg("mDNS discovery result")
		}
	}
	// do the arp check
	arp_results, err := arpDiscovery()
	if err != nil {
		log.Error().Err(err).Msg("ARP discovery failed")
	} else {
		matched_macs := checkARPMacs(config.Network.MACAddresses, arp_results.MACs)
		for _, mac := range matched_macs {
			log.Info().Str("mac", mac).Msg("Matched MAC address")
		}
	}

	// perform usb discovery
	usb_findings := checkUSBDevices(config.USB)
	for _, finding := range usb_findings {
		log.Info().
			Str("vendor", finding.Vendor).
			Str("manufacturer", finding.Manufacturer).
			Str("confidence", finding.Confidence).
			Msg("USB discovery result")
	}

	// perform http checks
	checkDomains := []string{}
	for _, m := range mdns {
		checkDomains = append(checkDomains, m.Domain)
		// remove IPs from IP list if the domain exists
		for _, ip := range m.IPv4s {
			ips := ip.String()
			ipIndex := slices.Index(arp_results.IPs, ips)
			if ipIndex != -1 {
				arp_results.IPs = append(arp_results.IPs[:ipIndex], arp_results.IPs[ipIndex+1:]...)
			}
		}
	}
	http_findings := httpQueries(arp_results.IPs, checkDomains, config.HTTP)
	for _, http_finding := range http_findings {
		log.Info().
			Str("vendor", http_finding.Vendor).
			Str("confidence", http_finding.Confidence).
			Str("type", http_finding.Type).
			Str("value", http_finding.Value).
			Str("hostname", http_finding.Hostname).
			Msg("http discovery result")
	}

}
