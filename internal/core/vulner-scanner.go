package core

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/Ullaakut/nmap/v3"
)

type Vulnerability struct {
	Identifier string
	CVSS       float64
	URL        string
	Exploit    bool
}

func Mock() {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(""),
		nmap.WithAggressiveScan(),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			for _, port := range h.Ports {
				if port.Status() == "open" {
					return true
				}
			}
			return false
		}),
		nmap.WithScripts("vulners"),
	)
	if err != nil {
		log.Fatalf("Не удалось создать сканер Nmap: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("Сканирование Nmap не удалось: %v", err)
	}

	if warnings != nil {
		fmt.Println("Предупреждения:")
		for _, warning := range *warnings {
			fmt.Println(warning)
		}
	}

	for _, host := range result.Hosts {
		fmt.Printf("Хост: %s\n", host.Addresses)

		for _, port := range host.Ports {
			fmt.Printf("Порт: %d/%s\n", port.ID, port.Protocol)
			fmt.Printf("Состояние: %s\n", port.State)

			for _, script := range port.Scripts {
				fmt.Printf("Скрипт: %s\n", script.ID)
				fmt.Printf("Вывод:\n%s\n", script.Output)

				if script.ID == "vulners" {
					vulnerabilities := parseVulnersOutput(script.Output)
					if len(vulnerabilities) > 0 {
						fmt.Println("Найденные уязвимости:")
						for _, vuln := range vulnerabilities {
							fmt.Printf("- Идентификатор: %s\n", vuln.Identifier)
							fmt.Printf("  CVSS: %.1f\n", vuln.CVSS)
							fmt.Printf("  Ссылка: %s\n", vuln.URL)
							if vuln.Exploit {
								fmt.Println("  Примечание: Есть доступные эксплойты")
							}
							fmt.Println()
						}
					} else {
						fmt.Println("Уязвимостей не найдено или не удалось распарсить вывод.")
					}
				}
			}
		}
	}
}

func parseVulnersOutput(output string) []Vulnerability {
	var vulnerabilities []Vulnerability

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// strings example:
		// CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
		// B8190CDB-3EB9-5631-9828-8064A1575B23    9.8     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  *EXPLOIT*

		re := regexp.MustCompile(`^(?P<id>\S+)\s+(?P<cvss>\d+(\.\d+)?)\s+(?P<url>\S+)(\s+\*EXPLOIT\*)?$`)
		match := re.FindStringSubmatch(line)

		if match == nil {
			continue
		}

		paramsMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && name != "" {
				paramsMap[name] = match[i]
			}
		}

		var cvss float64
		fmt.Sscanf(paramsMap["cvss"], "%f", &cvss)

		exploit := false
		if strings.Contains(line, "*EXPLOIT*") {
			exploit = true
		}

		vuln := Vulnerability{
			Identifier: paramsMap["id"],
			CVSS:       cvss,
			URL:        paramsMap["url"],
			Exploit:    exploit,
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Ошибка при сканировании вывода: %v", err)
	}

	return vulnerabilities
}
