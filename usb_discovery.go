package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

func getMacOsUSBDevices() string {
	// run ['ioreg', '-p', 'IOUSB', '-l', '-w', '0'] and return output as string
	out, err := exec.Command("ioreg", "-p", "IOUSB", "-l", "-w", "0").Output()
	if err != nil {
		log.Error().Err(err).Msg("subprocess to get USB devices failed")
	}
	return string(out)
}
func getLinuxUSBDevices() string {
	// run ['ioreg', '-p', 'IOUSB', '-l', '-w', '0'] and return output as string
	out, err := exec.Command("lsusb", "-v").Output()
	if err != nil {
		log.Error().Err(err).Msg("subprocess to get USB devices failed")
	}
	return string(out)
}

type USBFinding struct {
	Vendor       string
	Manufacturer string
	Confidence   string
}

func checkUSBDevices(usbIndicators map[string][]USBDevice) []USBFinding {
	findings := []USBFinding{}
	// get the usb devices
	var usboutput string
	if runtime.GOOS == "darwin" {
		usboutput = getMacOsUSBDevices()
		usboutput = strings.ToLower(usboutput)
	} else if runtime.GOOS == "linux" {
		usboutput = getLinuxUSBDevices()
		usboutput = strings.ToLower(usboutput)
	} else {
		log.Warn().Str("os", runtime.GOOS).Msg("USB discovery not supported on this OS")
		return findings
	}

	for vendor, devices := range usbIndicators {
		for _, device := range devices {
			// first check if the search string (manufacturer) is in the output
			if strings.Contains(usboutput, strings.ToLower(device.Manufacturer)) {
				f := USBFinding{
					Vendor:       vendor,
					Manufacturer: device.Manufacturer,
					Confidence:   "high",
				}
				findings = append(findings, f)
				log.Info().
					Str("vendor", vendor).
					Str("manufacturer", device.Manufacturer).
					Str("confidence", "high").
					Msg("Matched USB device manufacturer")
			}
			// next check for vid and pid
			if runtime.GOOS == "darwin" {
				// mac shows the vid and pid as ints and not hex so we need to convert
				macvid, err := strconv.ParseInt(device.VID, 16, 64)
				if err != nil {
					log.Error().Err(err).Msg("Failed to parse VID to int for macOS USB discovery")
					continue
				}
				macpid, err := strconv.ParseInt(device.PID, 16, 64)
				if err != nil {
					log.Error().Err(err).Msg("Failed to parse PID to int for macOS USB discovery")
					continue
				}
				vidstr := strconv.FormatInt(macvid, 10)
				pidstr := strconv.FormatInt(macpid, 10)
				if strings.Contains(usboutput, "\"idVendor\" = "+vidstr) && strings.Contains(usboutput, "\"idProduct\" = "+pidstr) {
					f := USBFinding{
						Vendor:       vendor,
						Manufacturer: device.Manufacturer,
						Confidence:   "low",
					}
					findings = append(findings, f)
					log.Info().
						Str("vendor", vendor).
						Str("manufacturer", device.Manufacturer).
						Str("confidence", "low").
						Msg("Matched USB device VID/PID")
				}
			} else if runtime.GOOS == "linux" {
				// match the following regex: ".*<vid>.*\n.*<pid>.*\n"
				r := fmt.Sprintf(".*%s.*\n.*%s.*\n", device.VID, device.PID)
				re, err := regexp.Compile(r) // Matches one or more digits
				if err != nil {
					panic(err)
				}
				match := re.FindStringSubmatch(usboutput)
				if len(match) > 0 {
					f := USBFinding{
						Vendor:       vendor,
						Manufacturer: device.Manufacturer,
						Confidence:   "low",
					}
					findings = append(findings, f)
					log.Info().
						Str("vendor", vendor).
						Str("manufacturer", device.Manufacturer).
						Str("confidence", "low").
						Msg("Matched USB device VID/PID")
				}
			}
			// check if the serial number is in the output
			if strings.Contains(usboutput, strings.ToLower(device.Serial)) {
				f := USBFinding{
					Vendor:       vendor,
					Manufacturer: device.Manufacturer,
					Confidence:   "medium",
				}
				findings = append(findings, f)
				log.Info().
					Str("vendor", vendor).
					Str("manufacturer", device.Manufacturer).
					Str("confidence", "medium").
					Msg("Matched USB device serial number")
			}
		}
	}

	return findings
}
