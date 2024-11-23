package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

type HandleProgress func()

func DiscoverHosts(ctx context.Context, ips []string, fn HandleProgress) ([]string, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(ips...),
		nmap.WithPingScan(),
	)
	if err != nil {
		return nil, err
	}
	progress := make(chan float32, 1)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case _, ok := <-progress:
				if !ok {
					return
				}
			case <-ticker.C:
				fn()
			case <-ctx.Done():
				return
			}
		}
	}()

	result, warnings, err := scanner.Progress(progress).Run()
	if err != nil {
		return nil, err
	}

	if len(*warnings) > 0 {
		log.Printf("Warnings during discovering hosts: %v\n", warnings)
	}

	var discoveriesIps []string
	for _, host := range result.Hosts {
		discoveriesIps = append(discoveriesIps, host.Addresses[0].Addr)
	}

	return discoveriesIps, nil
}

func ResolveDomain(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ip := range ips {
		results = append(results, ip.String())
	}
	return results, nil
}

func ResolveIpAddr(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	var results []string
	results = append(results, names...)
	return results, nil
}

type Subdomain struct {
	Domain string
	IPs    []string
}

func parseDNSBruteOutput(output string) ([]Subdomain, error) {
	var subdomains []Subdomain
	subdomainMap := make(map[string]map[string]struct{})

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "DNS Brute-force hostnames:") {
			continue
		}

		if strings.HasPrefix(line, "*") {
			continue
		}

		parts := strings.Split(line, " - ")
		if len(parts) < 2 {
			log.Printf("Пропущена строка из-за некорректного формата: %s", line)
			continue
		}

		subdomain := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])

		if _, exists := subdomainMap[subdomain]; !exists {
			subdomainMap[subdomain] = make(map[string]struct{})
		}

		if ip != "" {
			subdomainMap[subdomain][ip] = struct{}{}
		}
	}

	for domain, ipsMap := range subdomainMap {
		var ips []string
		for ip := range ipsMap {
			ips = append(ips, ip)
		}
		subdomains = append(subdomains, Subdomain{
			Domain: domain,
			IPs:    ips,
		})
	}

	return subdomains, nil
}

func FindSubdomains(ctx context.Context, domain []string, fn HandleProgress) ([]Subdomain, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(domain...),
		nmap.WithScripts("dns-brute"),
		nmap.WithDisabledDNSResolution(),
	)
	if err != nil {
		return nil, fmt.Errorf("error while starting nmap in find subdomains func: %v", err)
	}

	progress := make(chan float32, 1)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case _, ok := <-progress:
				if !ok {
					return
				}
			case <-ticker.C:
				fn()
			case <-ctx.Done():
				return
			}
		}
	}()

	result, warnings, err := scanner.Progress(progress).Run()
	if err != nil {
		return nil, fmt.Errorf("error while starting nmap in find subdomains func: %v", err)
	}

	if len(*warnings) > 0 {
		log.Printf("Nmap warning: %v\n", *warnings)
	}

	var subdomains []Subdomain

	for _, host := range result.Hosts {
		for _, script := range host.HostScripts {
			if script.ID == "dns-brute" {
				subdomains, err = parseDNSBruteOutput(script.Output)
				if err != nil {
					return nil, fmt.Errorf("error while parse dns brute output: %v", err)
				}
			}
		}
	}

	return subdomains, nil
}

func BasePortScan(ctx context.Context, ips []string, fn HandleProgress) (map[string][]int, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(ips...),
		nmap.WithSkipHostDiscovery(),
		nmap.WithOpenOnly(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	progress := make(chan float32, 1)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case _, ok := <-progress:
				if !ok {
					return
				}
			case <-ticker.C:
				fn()
			case <-ctx.Done():
				return
			}
		}
	}()

	result, warnings, err := scanner.Progress(progress).Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings)
	}

	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	portMap := make(map[string][]int)
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		hostName := host.Addresses[0].Addr
		if _, exists := portMap[hostName]; !exists {
			portMap[hostName] = []int{}
		}
		for _, port := range host.Ports {
			portMap[hostName] = append(portMap[hostName], int(port.ID))
		}
	}
	return portMap, nil
}
