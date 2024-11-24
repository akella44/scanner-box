package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"scanner-box/internal/models"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

func VulnerUdpScan(ip string, portCount int, fn HandleProgress) ([]models.VulnerScanOutputItem, error) {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithUDPScan(),
		nmap.WithTargets(ip),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithSkipHostDiscovery(),
		nmap.WithOpenOnly(),
		nmap.WithScripts("vulners"),
		nmap.WithMostCommonPorts(portCount),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("Nmap scan failed: %v", err)
	}

	if warnings != nil {
		log.Println("Warnings:")
		for _, warning := range *warnings {
			log.Println(warning)
		}
	}

	var scanResults []models.VulnerScanOutputItem

	for _, host := range result.Hosts {
		hostIP := ""
		for _, address := range host.Addresses {
			hostIP = address.Addr
			break
		}

		for _, port := range host.Ports {
			portID := port.ID
			portProtocol := port.Protocol

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					items := parseVulnerabilities(script.Tables, hostIP, portID, fmt.Sprintf("%v %v", port.Service, port.Service.Version), models.Protocol(portProtocol))
					scanResults = append(scanResults, items...)
				}
			}
		}
	}

	return scanResults, nil
}

func VulnerTcpScan(ctx context.Context, ip string, portCount int, fn HandleProgress) ([]models.VulnerScanOutputItem, error) {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(ip),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithSkipHostDiscovery(),
		nmap.WithOpenOnly(),
		nmap.WithScripts("vulners"),
		nmap.WithMostCommonPorts(portCount),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nmap scanner: %v", err)
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
		return nil, fmt.Errorf("Nmap scan failed: %v", err)
	}

	if warnings != nil {
		log.Println("Warnings:")
		for _, warning := range *warnings {
			log.Println(warning)
		}
	}

	var scanResults []models.VulnerScanOutputItem

	for _, host := range result.Hosts {
		hostIP := ""
		for _, address := range host.Addresses {
			hostIP = address.Addr
			break
		}

		for _, port := range host.Ports {
			portID := port.ID
			portProtocol := port.Protocol

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					items := parseVulnerabilities(script.Tables, hostIP, portID, fmt.Sprintf("%v %v", port.Service, port.Service.Version), models.Protocol(portProtocol))
					scanResults = append(scanResults, items...)
				}
			}

		}
	}

	return scanResults, nil
}

func parseVulnerabilities(tables []nmap.Table, ip string, port uint16, service string, protocol models.Protocol) []models.VulnerScanOutputItem {
	var vulnerabilities []models.VulnerScanOutputItem
	currentVulnIndex := -1

	for _, cpeTable := range tables {
		cpe := cpeTable.Key
		for _, vulnTable := range cpeTable.Tables {
			var (
				isExploit   bool
				id          string
				cvss        float64
				vulnType    string
				title       string
				description string
				url         string
			)

			for _, elem := range vulnTable.Elements {
				switch strings.ToLower(elem.Key) {
				case "is_exploit":
					if val, err := strconv.ParseBool(elem.Value); err == nil {
						isExploit = val
					} else {
						fmt.Printf("Error parsing is_exploit: %v\n", err)
					}
				case "id":
					id = elem.Value
				case "cvss":
					if val, err := strconv.ParseFloat(elem.Value, 64); err == nil {
						cvss = val
					} else {
						fmt.Printf("Error parsing cvss: %v\n", err)
					}
				case "type":
					vulnType = strings.ToLower(elem.Value)
				case "title":
					title = elem.Value
				case "description":
					description = elem.Value
				case "url":
					url = elem.Value
				}
			}

			if !isExploit && vulnType == "cve" {
				vulnerability := models.VulnerScanOutputItem{
					IP:            ip,
					Port:          port,
					Protocol:      protocol,
					Service:       service,
					CPE:           cpe,
					CVEidentifier: id,
					CVSS:          cvss,
					Title:         title,
					Description:   description,
					Exploits:      []models.Exploit{},
				}
				vulnerabilities = append(vulnerabilities, vulnerability)
				currentVulnIndex = len(vulnerabilities) - 1
			} else if isExploit {
				if currentVulnIndex >= 0 && currentVulnIndex < len(vulnerabilities) {
					exploit := models.Exploit{
						CVSS: cvss,
						Url:  url,
					}
					vulnerabilities[currentVulnIndex].Exploits = append(vulnerabilities[currentVulnIndex].Exploits, exploit)
				}
			}
		}
	}

	return vulnerabilities
}

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
		log.Printf("Nmap warnings after start: %v\n", warnings)
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
			log.Printf("Skipping row while dns brute: %s", line)
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
		log.Printf("Nmap warnings after start: %v\n", *warnings)
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
		log.Printf("Nmap warnings after start: %s\n", *warnings)
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
