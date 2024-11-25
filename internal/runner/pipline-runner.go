package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"scanner-box/internal/core"
	"scanner-box/internal/models"
	"scanner-box/internal/poolmanager"
	"scanner-box/internal/utils"
	"strings"
	"sync"
	"time"
)

func terif[T any](cond bool, Then T, Else T) T {
	if cond {
		return Then
	} else {
		return Else
	}
}

func deduplicateInts(input []int) []int {
	seen := make(map[int]struct{})
	var result []int
	for _, num := range input {
		if _, exists := seen[num]; !exists {
			seen[num] = struct{}{}
			result = append(result, num)
		}
	}
	return result
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
						Ports:  deduplicateInts(openPorts[host]),
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
						Ports:  deduplicateInts(aggregatedPorts),
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

func RunVulnersScan(ctx context.Context, portsCount int, ips []string, fn core.HandleProgress) ([]models.VulnerScanOutputItem, error) {
	pm, err := poolmanager.GetPool()

	if err != nil {
		return nil, fmt.Errorf("failed to get PoolManager: %v", err)
	}

	resultCh := make(chan []models.VulnerScanOutputItem, len(ips))
	errCh := make(chan error, len(ips))

	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)

		task := poolmanager.VulnerScanTask{
			IP:              ip,
			PortCount:       portsCount,
			ResultCh:        resultCh,
			ErrCh:           errCh,
			ProgressHandler: fn,
			Wg:              &wg,
		}

		err := pm.SubmitTask(task)
		if err != nil {
			wg.Done()
			log.Printf("Failed to submit task for IP %s: %v", ip, err)
			errCh <- fmt.Errorf("failed to submit task for IP %s: %v", ip, err)
		}
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	var allResults []models.VulnerScanOutputItem
	var firstErr error

	for {
		select {
		case res, ok := <-resultCh:
			if !ok {
				resultCh = nil
			} else {
				allResults = append(allResults, res...)
			}
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
			} else {
				if firstErr == nil {
					firstErr = err
				}
				log.Printf("Error: %v\n", err)
			}
		}

		if resultCh == nil && errCh == nil {
			break
		}
	}

	progress := make(chan float32, len(allResults))

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

	type Result struct {
		Index       int
		Description string
	}

	resultsCh := make(chan Result, len(allResults))
	var wgFetch sync.WaitGroup

	semaphore := make(chan struct{}, (int)(len(allResults)/3))

	for i := range allResults {
		i := i
		wgFetch.Add(1)
		go func() {
			defer wgFetch.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			time.Sleep(time.Duration(rand.IntN(1000)+1000) * time.Millisecond)
			description, err := fetchCveDescription(allResults[i].CVEidentifier)
			if err != nil {
				log.Printf("Failed during fetch cve description %v", err)
				return
			}
			resultsCh <- Result{Index: i, Description: description}
			progress <- (float32)(i / len(allResults))
		}()
	}
	go func() {
		wgFetch.Wait()
		close(resultsCh)
	}()
	for result := range resultsCh {
		allResults[result.Index].Description = result.Description
	}
	return allResults, firstErr
}

func fetchCveDescription(cveID string) (string, error) {
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API responded with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read API response: %v", err)
	}

	var apiResponse models.NvdApiData
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal API response: %v", err)
	}

	for _, vulner := range apiResponse.Vulnerabilities {
		if strings.EqualFold(vulner.CVE.ID, cveID) {
			for _, description := range vulner.CVE.Descriptions {
				if description.Lang == "en" {
					return description.Value, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no eng description for CVE %s", cveID)
}
