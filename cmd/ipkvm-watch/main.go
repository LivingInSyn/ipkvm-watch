package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"slices"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Indicators struct {
}

type Results struct {
	MDNS         []MDNSResult  `json:"mdns"`
	ARPResults   []ARPResult   `json:"arp"`
	USBFindings  []USBFinding  `json:"usb"`
	HTTPFindings []HTTPFinding `json:"http"`
}

func main() {
	configPath := flag.String("i", "indicators.yaml", "path to the indicators yaml file")
	debugF := flag.Bool("d", false, "turn on debug (verbose) logging")
	noMdnsListen := flag.Bool("m", false, "if set, no mdns ports will be opened and only subprocesses will be used")
	flag.Parse()

	// This is a placeholder for the main function.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *debugF {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Info().Msg("Starting network discovery")

	// load the indicators.yaml file
	config := GetConfig(*configPath)

	// create the output obj
	r := Results{}

	// perform mdns discovery
	var mdns []MDNSResult
	var err error
	if !*noMdnsListen {
		mdns, err = resolveMDNSNames(config.Network.MDNS)
	} else {
		mdns, err = mDNSDiscoverySubp(config.Network.MDNS)
	}
	if err != nil {
		log.Error().Err(err).Msg("mDNS discovery failed")
	} else {
		r.MDNS = mdns
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
		r.ARPResults = matched_macs
		for _, mac := range matched_macs {
			log.Info().Str("mac", mac.MAC).Msg("Matched MAC address")
		}
	}

	// perform usb discovery
	usb_findings := checkUSBDevices(config.USB)
	r.USBFindings = usb_findings
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
	r.HTTPFindings = http_findings
	for _, http_finding := range http_findings {
		log.Info().
			Str("vendor", http_finding.Vendor).
			Str("confidence", http_finding.Confidence).
			Str("type", http_finding.Type).
			Str("value", http_finding.Value).
			Str("hostname", http_finding.Hostname).
			Msg("http discovery result")
	}

	// format the output and write it as json
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal results as json")
	}
	fmt.Print(string(b))

}
