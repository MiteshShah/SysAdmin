package main

import (
	"fmt"
	"github.com/miekg/dns"
	"os"
)

// ANSI color codes
const (
	Reset = "\033[0m"
	Red   = "\033[31m"
	Green = "\033[32m"
	Blue  = "\033[34m"
	White = "\033[97m"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain> [dns_server]")
		os.Exit(1)
	}

	domain := os.Args[1]
	var dnsServer string

	if len(os.Args) >= 3 {
		// Use the provided DNS server if available
		dnsServer = os.Args[2]
	} else {
		// Use the default DNS server if no custom DNS server is provided
		dnsServer = ""
	}

	_, err := LookupDomain(domain, dnsServer)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", Red, err, Reset)
	}
}

// DNSResponse represents the response from a DNS lookup.
type DNSResponse struct {
	DNSServer string
	Records   []dns.RR
}

func LookupDomain(domain, dnsServer string) (*DNSResponse, error) {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	if dnsServer != "" {
		// Use the custom DNS server if provided
		config.Servers = []string{dnsServer}
	}

	c := new(dns.Client)
	// Use TCP for DNS queries
	// With Default UDP few domain TXT record are not shown
	c.Net = "tcp"

	// Additional DNS types
	types := []uint16{dns.TypeNS, dns.TypeDNSKEY, dns.TypeCAA, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeSOA, dns.TypeSPF}

	var records []dns.RR
	// Now you can print the final results after the loop
	fmt.Printf("%sDNS Server Used: %s%s\n", Green, config.Servers[0], Reset)

	for _, t := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), t)
		m.RecursionDesired = true

		fmt.Print("\n")
		fmt.Printf("%s%s %s\n", Blue, domain, dns.TypeToString[t])
		r, _, err := c.Exchange(m, config.Servers[0]+":"+config.Port)
		if err != nil {
			return nil, err
		}

		if r.Rcode == dns.RcodeSuccess {
			records = append(records, r.Answer...)

			// Print DNS records specifically
			for _, record := range r.Answer {
				fmt.Printf("%s%v%s\n", White, record, Reset)
			}
		}
	}

	// List of subdomains to check
	subdomainstypes := []uint16{dns.TypeTXT}

	subdomains := []string{"_dmarc", "_acme-challenge"}

	for _, subdomain := range subdomains {
		for _, t := range subdomainstypes {
			fullSubdomain := fmt.Sprintf("%s.%s", subdomain, domain)

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(fullSubdomain), t)
			m.RecursionDesired = true

			fmt.Print("\n")
			fmt.Printf("%s%s %s\n", Blue, fullSubdomain, dns.TypeToString[t])
			r, _, err := c.Exchange(m, config.Servers[0]+":"+config.Port)
			if err != nil {
				return nil, err
			}

			if r.Rcode == dns.RcodeSuccess {
				records = append(records, r.Answer...)

				// Print DNS records specifically
				for _, record := range r.Answer {
					fmt.Printf("%s%v%s\n", White, record, Reset)
				}
			}
		}
	}
	if len(records) == 0 {
		fmt.Println("No DNS Records found.")
	}

	return &DNSResponse{
		DNSServer: config.Servers[0],
		Records:   records,
	}, nil
}
