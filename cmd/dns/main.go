package main

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
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

func LookupDomain(domain, customDNS string) (*DNSResponse, error) {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	if customDNS != "" {
		// Use the custom DNS server if provided
		config.Servers = []string{customDNS}
	}

	client := new(dns.Client)
	// Use TCP for DNS queries
	// With Default UDP, few domain TXT records are not shown
	client.Net = "tcp"

	// Additional DNS types
	dnsTypes := []uint16{dns.TypeNS, dns.TypeDNSKEY, dns.TypeCAA, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeSOA, dns.TypeSPF}

	var records []dns.RR
	// Now you can print the final results after the loop
	fmt.Printf("%sDNS Server Used: %s%s\n", Green, config.Servers[0], Reset)

	for _, recordType := range dnsTypes {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), recordType)
		message.RecursionDesired = true

		fmt.Print("\n")
		fmt.Printf("%s%s %s\n", Blue, domain, dns.TypeToString[recordType])
		response, _, err := client.Exchange(message, config.Servers[0]+":"+config.Port)
		if err != nil {
			return nil, err
		}

		if response.Rcode == dns.RcodeSuccess {
			records = append(records, response.Answer...)

			// Print DNS records specifically
			for _, dnsRecord := range response.Answer {
				fmt.Printf("%s%v%s\n", White, dnsRecord, Reset)
			}
		}
	}

	// List of subdomains to check
	subdomainTypes := []uint16{dns.TypeTXT}

	subdomains := []string{"_dmarc", "_acme-challenge"}

	for _, subdomain := range subdomains {
		for _, subdomainType := range subdomainTypes {
			fullSubdomain := fmt.Sprintf("%s.%s", subdomain, domain)

			message := new(dns.Msg)
			message.SetQuestion(dns.Fqdn(fullSubdomain), subdomainType)
			message.RecursionDesired = true

			fmt.Print("\n")
			fmt.Printf("%s%s %s\n", Blue, fullSubdomain, dns.TypeToString[subdomainType])
			response, _, err := client.Exchange(message, config.Servers[0]+":"+config.Port)
			if err != nil {
				return nil, err
			}

			if response.Rcode == dns.RcodeSuccess {
				records = append(records, response.Answer...)

				// Print DNS records specifically
				for _, dnsRecord := range response.Answer {
					fmt.Printf("%s%v%s\n", White, dnsRecord, Reset)
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
