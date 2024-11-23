package runner

import (
	"context"
	"fmt"
	"log"
	"scanner-box/internal/core"
	"scanner-box/internal/models"
	"scanner-box/internal/utils"
	"sync"
)

func terif[T any](cond bool, Then T, Else T) T {
	if cond {
		return Then
	} else {
		return Else
	}
}

func RunDiscoverPipline(assetsValues []string, fn core.HandleProgress) ([]models.DiscoveryScanOutputItem, error) {
	assets, err := utils.ParseAssets(assetsValues)
	if err != nil {
		return nil, fmt.Errorf("parsing assets value failed %v", err)
	}

	var result []models.DiscoveryScanOutputItem
	var wg sync.WaitGroup
	var rwmu sync.RWMutex

	errCh := make(chan error, len(assetsValues))

	for targetType, assetList := range assets {
		switch targetType {
		case models.CIDR, models.IP:
			wg.Add(1)
			go func(assets []string) {
				defer wg.Done()
				hosts, err := core.DiscoverHosts(context.Background(), assets, fn)
				if err != nil {
					errCh <- fmt.Errorf("failed find hosts with following err %v", err)
					return
				}
				openPorts, err := core.BasePortScan(context.Background(), hosts, fn)
				if err != nil {
					errCh <- fmt.Errorf("failed base scanning ports following err %v", err)
					return
				}
				for _, host := range hosts {
					domain, err := core.ResolveIpAddr(host)
					if err != nil {
						log.Printf("Failed find hostname for ip addr %v", err)
						domain = []string{""}
					}
					rwmu.Lock()
					result = append(result, models.DiscoveryScanOutputItem{
						Domain: terif(len(domain) > 0, domain[0], ""),
						IPs:    []string{host},
						Ports:  openPorts[host],
					})
					log.Println(result)
					rwmu.Unlock()
				}
			}(assetList)
		case models.Domain:
			wg.Add(1)
			go func(assets []string) {
				defer wg.Done()
				subdomains, err := core.FindSubdomains(context.Background(), assets, fn)
				if err != nil {
					errCh <- fmt.Errorf("failed find subdomains with following err %v", err)
					return
				}
				ipSet := make(map[string]struct{})
				for _, subdomain := range subdomains {
					for _, ip := range subdomain.IPs {
						ipSet[ip] = struct{}{}
					}
				}

				var uniqueIPs []string
				for ip := range ipSet {
					uniqueIPs = append(uniqueIPs, ip)
				}

				portsMap, err := core.BasePortScan(context.Background(), uniqueIPs, fn)
				if err != nil {
					errCh <- fmt.Errorf("failed port scan: %v", err)
					return
				}

				rwmu.Lock()
				for _, subdomain := range subdomains {
					var aggregatedPorts []int
					for _, ip := range subdomain.IPs {
						if ports, exists := portsMap[ip]; exists {
							aggregatedPorts = append(aggregatedPorts, ports...)
						}
					}
					result = append(result, models.DiscoveryScanOutputItem{
						Domain: subdomain.Domain,
						IPs:    subdomain.IPs,
						Ports:  aggregatedPorts,
					})
				}
				rwmu.Unlock()
			}(assetList)
		}
	}
	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		log.Fatalf("Fatal error while executing discovery funcs %v", err)
	}
	wg.Wait()
	return result, nil
}
