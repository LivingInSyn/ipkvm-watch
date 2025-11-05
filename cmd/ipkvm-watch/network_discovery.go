package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pion/mdns/v2"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Discovery has a few phases
// 1. ARP to gather IPs on the same broadcast domain
// 2. mDNS lookups for indicator domains

type ARPDiscovery struct {
	IPs  []string
	MACs []string
}
type ARPResult struct {
	MAC    string
	Vendor string
}
type MDNSResult struct {
	Domain string
	Vendor string
	IPv4s  []net.IP
	IPv6s  []*net.IPAddr
}

var IP_EXCLUSION = []string{
	"224.0.0.251",
	"239.255.255.250",
	"169.254.169.254",
}

func parseArpWindows(arpInput string) (ARPDiscovery, error) {
	ips := []string{}
	macs := []string{}
	// sample input
	// Interface: 172.26.176.1 --- 0x48
	//   Internet Address      Physical Address      Type
	//   172.26.182.63         00-15-5d-e8-bf-8b     dynamic
	//   172.26.191.255        ff-ff-ff-ff-ff-ff     static
	for _, line := range strings.Split(arpInput, "\n") {
		// skip lines without double spaces, those are interface defs
		// and headers (Internet Address....)
		if strings.HasPrefix(line, "Interface ") || strings.HasPrefix(line, "  Internet ") {
			continue
		}
		//
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			mac := fields[1]
			// windows returns MACs with dashes and indicators are written with colons
			// so we're going to replace - with : on the macs
			mac = strings.Replace(mac, "-", ":", -1)
			ips = append(ips, ip)
			macs = append(macs, mac)
		}
	}
	return ARPDiscovery{
			IPs:  ips,
			MACs: macs,
		},
		nil
}
func parseArpNixMac(arpInput string) (ARPDiscovery, error) {
	ips := []string{}
	macs := []string{}
	for _, line := range strings.Split(arpInput, "\n") {
		// parse line to get IP address
		// sample line is "? (192.168.68.56) at e6:c0:b:4b:d:26 on en0 ifscope "
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// get the IP
			ip := strings.Trim(parts[1], "()")
			if slices.Contains(IP_EXCLUSION, ip) {
				continue
			}
			log.Debug().Str("IP", ip).Msg("Discovered IP via ARP")
			ips = append(ips, ip)
			// get the MAC
			mac := parts[3]
			log.Debug().Str("MAC", mac).Msg("Discovered MAC via ARP")
			macs = append(macs, mac)
		}
	}
	return ARPDiscovery{
			IPs:  ips,
			MACs: macs,
		},
		nil
}

func arpDiscovery() (ARPDiscovery, error) {
	// run arp -a and parse output
	cmd := exec.Command("arp", "-a")
	stdout, err := cmd.Output()
	if err != nil {
		log.Err(err).Msg("Failed to run arp command")
		return ARPDiscovery{}, err
	}
	// for each line in stdout get the IP address
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		return parseArpNixMac(string(stdout))
	} else if runtime.GOOS == "windows" {
		return parseArpWindows(string(stdout))
	} else {
		log.Error().Str("os", runtime.GOOS).Msg("ARP discovery not supported on this OS")
		return ARPDiscovery{}, fmt.Errorf("failed to perform ARP discovery")
	}
}

func checkARPMacs(mac_indicators map[string]MACPrefixGroup, discovered_macs []string) []ARPResult {
	matched_vendors := []ARPResult{}
	for vendor, prefix_group := range mac_indicators {
		for _, prefix_entry := range prefix_group.Prefixes {
			prefix := strings.ToLower(prefix_entry.Prefix)
			for _, discovered_mac := range discovered_macs {
				discovered_mac = strings.ToLower(discovered_mac)
				if strings.HasPrefix(discovered_mac, prefix) {
					a := ARPResult{
						MAC:    discovered_mac,
						Vendor: vendor,
					}
					log.Info().Str("MAC", discovered_mac).Str("vendor", vendor).Msg("Matched MAC prefix")
					matched_vendors = append(matched_vendors, a)
				}
			}
		}
	}
	return matched_vendors
}

// func mDNSDiscoveryMacOS(domains []string) ([]string, error) {
// 	found_domains := []string{}
// 	for _, domain := range domains {
// 		cmd := exec.Command("dscacheutil", "-q", "host", "-a", "name", domain)
// 		stdout, err := cmd.Output()
// 		if err != nil {
// 			log.Err(err).Str("domain", domain).Msg("Failed to run dscacheutil command")
// 			continue
// 		}
// 		if string(stdout) != "" {
// 			log.Debug().Str("domain", domain).Msg("Discovered domain via mDNS")
// 			found_domains = append(found_domains, domain)
// 		}
// 	}
// 	return found_domains, nil
// }

func resolveMDNSNames(mdns_indicators map[string][]string) ([]MDNSResult, error) {
	found_domains := []MDNSResult{}
	// build the things we need for mdns resolution
	// ipv4
	addr4, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
	if err != nil {
		return found_domains, err
	}
	l4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		return found_domains, err
	}
	packetConnV4 := ipv4.NewPacketConn(l4)
	// make a nil ipv6 packet conn
	var packetConnV6 *ipv6.PacketConn
	// create the mdns server
	server, err := mdns.Server(packetConnV4, packetConnV6, &mdns.Config{})
	if err != nil {
		return found_domains, err
	}
	//now iterate over the domains
	for vendor, domains := range mdns_indicators {
		for _, domain := range domains {
			mdns_result := MDNSResult{
				Domain: domain,
				Vendor: vendor,
				IPv4s:  []net.IP{},
				IPv6s:  []*net.IPAddr{},
			}

			// perform query
			// create a context with a 3 second timeout
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()
			answer, src, err := server.QueryAddr(ctx, domain)
			if err != nil {
				log.Debug().Err(err).Str("hostname", domain).Msg("mDNS query failed")
				continue
			}
			log.Info().Str("answer", answer.GoString()).Str("src", src.String()).Msg("mDNS query result")

			found_domains = append(found_domains, mdns_result)
		}
	}
	return found_domains, nil
}
