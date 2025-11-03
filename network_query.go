package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
)

type PageSearchElement int

const (
	Title PageSearchElement = iota
	Favicon
)

type HTTPFinding struct {
	Vendor     string
	Confidence string
	Type       string
	Value      string
	Hostname   string
}

func httpQueries(ips []string, domainNames []string, indicators HTTPConfig) []HTTPFinding {
	httpFindings := []HTTPFinding{}
	// make HTTP requests and check the title ssl certs
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	//combine ips and domains into a single list of targets
	combined_targets := append(ips, domainNames...)
	// check the cert
	for _, target := range combined_targets {
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", target), conf)
		if err != nil {
			log.Error().Err(err).Str("target", target).Msg("Error in Dial for SSL check")
			continue
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			// check org and org unit against indicators
			for vendor, indicator_org := range indicators.SSL {
				for _, certorg := range cert.Issuer.Organization {
					if strings.Contains(certorg, indicator_org) {
						f := HTTPFinding{
							Vendor:     vendor,
							Confidence: "high",
							Type:       "SSL",
							Value:      certorg,
							Hostname:   target,
						}
						httpFindings = append(httpFindings, f)
						log.Info().
							Str("vendor", f.Vendor).
							Str("confidence", f.Confidence).
							Str("type", f.Type).
							Str("value", f.Value).
							Str("hostname", f.Hostname).
							Msg("SSL certificate match found")
					}
				}
			}

		}
	}
	// check the page title
	for _, target := range combined_targets {
		url := fmt.Sprintf("https://%s", target)
		title, err := getPageElement(url, Title)
		if err != nil {
			log.Error().Err(err).Str("url", url).Msg("Error fetching title")
			continue
		}
		// check title against indicators
		for vendor, titles := range indicators.Title {
			for _, indicator_title := range titles {
				if strings.Contains(title, indicator_title) {
					f := HTTPFinding{
						Vendor:     vendor,
						Confidence: "medium",
						Type:       "Title",
						Value:      title,
						Hostname:   target,
					}
					httpFindings = append(httpFindings, f)
					log.Info().
						Str("vendor", f.Vendor).
						Str("confidence", f.Confidence).
						Str("type", f.Type).
						Str("value", f.Value).
						Str("hostname", f.Hostname).
						Msg("Page title match found")
				}
			}
		}
		// finally, check the favicon

	}
	// check the favicon
	for _, target := range combined_targets {
		url := fmt.Sprintf("https://%s", target)
		favicon_hash, err := getFaviconHash(url)
		if err != nil {
			log.Error().Err(err).Str("url", url).Msg("Error fetching favicon")
			continue
		}
		for vendor, hashes := range indicators.Favicon {
			for _, hash := range hashes {
				if hash == favicon_hash {
					f := HTTPFinding{
						Vendor:     vendor,
						Confidence: "high",
						Type:       "Favicon",
						Value:      favicon_hash,
						Hostname:   target,
					}
					httpFindings = append(httpFindings, f)
					log.Info().
						Str("vendor", f.Vendor).
						Str("confidence", f.Confidence).
						Str("type", f.Type).
						Str("value", f.Value).
						Str("hostname", f.Hostname).
						Msg("Page title match found")
				}
			}
		}
	}
	return httpFindings
}

func getFaviconHash(url string) (string, error) {
	// try to parse the favicon localtion from the page
	favicon_loc, err := getPageElement("https://glkvm.local", Favicon)
	if err != nil {
		log.Info().Err(err).Msg("Error getting favicon location. Trying /favicon.ico")
		favicon_loc = "/favicon.ico"
	}
	log.Info().Str("favicon_loc", favicon_loc).Msg("Favicon location parsed")
	// if the favicon_loc is a relative path, append it to the base url
	if strings.HasPrefix(favicon_loc, "/") {
		url = strings.TrimRight(url, "/") + favicon_loc
	} else if strings.HasPrefix(favicon_loc, "http") {
		url = favicon_loc
	} else {
		url = strings.TrimRight(url, "/") + "/" + favicon_loc
	}
	// 1. Fetch the favicon
	customTransport := http.DefaultTransport.(*http.Transport).Clone()      // Clone default transport to keep other settings
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Ignore SSL verification

	// Create an HTTP client with the custom transport
	client := &http.Client{Transport: customTransport}
	resp, err := client.Get(url)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching favicon")
		return "", fmt.Errorf("error fetching URL: %w", err)
	}
	defer resp.Body.Close()

	// 2. Read the favicon data
	faviconData := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(faviconData)
	if err != nil {
		log.Error().Err(err).Msg("Error reading favicon data")
		return "", err
	}

	// calculate an md5 hash of the faviconData
	// you may ask why MD5 and not the shodan hash format. The answer is because
	// the shodan ico hash format is a f'ing nightmare
	// see: https://gist.github.com/hdm/1552cdfad14b32a2d2f44a64468558c5#file-mmh3-go-L78
	// https://mastodon.shodan.io/@shodan/111324484216158638
	hasher := md5.New()
	hasher.Write(faviconData)
	md5HashString := hex.EncodeToString(hasher.Sum(nil))
	return md5HashString, nil
}

func getPageElement(url string, searchElement PageSearchElement) (string, error) {
	// 1. Fetch the webpage
	customTransport := http.DefaultTransport.(*http.Transport).Clone()      // Clone default transport to keep other settings
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Ignore SSL verification

	// Create an HTTP client with the custom transport
	client := &http.Client{Transport: customTransport}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("error fetching URL: %w", err)
	}
	// Ensure the response body is closed after the function exits
	defer resp.Body.Close()

	// Check for a successful HTTP status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	// 2. Parse the HTML body
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML: %w", err)
	}

	// 3. Find and extract the title
	return_element := ""
	//favico := ""
	var f func(*html.Node)
	f = func(n *html.Node) {
		// Check for the <title> tag
		if searchElement == Title {
			if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
				return_element = n.FirstChild.Data
				return // Found the title, stop recursion/search
			}
		} else if searchElement == Favicon {
			if n.Type == html.ElementNode && n.Data == "link" {
				// Check for rel="icon" or rel="shortcut icon"
				var isFavicon bool
				var href string
				for _, attr := range n.Attr {
					if attr.Key == "rel" && (attr.Val == "icon" || attr.Val == "shortcut icon") {
						isFavicon = true
					}
					if attr.Key == "href" {
						href = attr.Val
					}
				}
				if isFavicon {
					//favico = href
					return_element = href
					return // Found the favicon, stop recursion/search
				}
			}
		}
		// Recursively search children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
			if return_element != "" { // If title was found in a child call, stop searching siblings
				return
			}
		}
	}
	f(doc)

	if return_element == "" {
		return "", fmt.Errorf("title tag not found or is empty")
	}

	return return_element, nil
}
