package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"scanner-box/config"
	"scanner-box/internal/models"
	"scanner-box/internal/runner"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	Config *config.Config
}

func NewHostDiscoveryHandler(cfg *config.Config) *Handler {
	return &Handler{Config: cfg}
}

func (h *Handler) HostDiscoveryScanHandler(c *gin.Context) {
	var req models.DiscoveryScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	apiKey := h.Config.ApiKey

	go func(req models.DiscoveryScanRequest) {
		client := &http.Client{}

		items, err := runner.RunDiscoverPipline(req.Targets, func() {
			keepAliveURL := fmt.Sprintf("%v/api/assets/%d/host-scans/keep-alive/", h.Config.BackendAPIBaseURL, req.AssetID)
			req, err := http.NewRequest("POST", keepAliveURL, nil)
			if err != nil {
				log.Printf("Error creating keep-alive request: %v", err)
				return
			}
			req.Header.Set("Authorization", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Error sending keep-alive request: %v", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("Keep-alive request failed with status code: %d", resp.StatusCode)
			}
		})
		if err != nil {
			log.Printf("Discovery scan failed: %v", err)
			return
		}

		body, err := json.Marshal(items)
		if err != nil {
			log.Printf("Error marshalling scan results: %v", err)
			return
		}

		resultsURL := fmt.Sprintf("%v/api/assets/%d/host-scans/", h.Config.BackendAPIBaseURL, req.AssetID)
		resultReq, err := http.NewRequest("POST", resultsURL, bytes.NewBuffer(body))
		if err != nil {
			log.Printf("Error creating results request: %v", err)
			return
		}
		resultReq.Header.Set("Content-Type", "application/json")
		resultReq.Header.Set("Authorization", apiKey)

		resp, err := client.Do(resultReq)
		if err != nil {
			log.Printf("Error sending scan results: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to send scan results, status code: %d", resp.StatusCode)
		}
	}(req)

	c.JSON(http.StatusOK, gin.H{"status": "Scan initiated"})
}

func (h *Handler) VulnerabilityScanHandler(c *gin.Context) {
	var req models.VulnerScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	apiKey := h.Config.ApiKey

	go func(req models.VulnerScanRequest) {
		client := &http.Client{}

		items, err := runner.RunVulnersScan(context.Background(), 1000, req.Targets, func() {
			keepAliveURL := fmt.Sprintf("%v/api/vulnerability-scans/%d/cves/keep-alive/", h.Config.BackendAPIBaseURL, req.AssetID)
			req, err := http.NewRequest("POST", keepAliveURL, nil)
			if err != nil {
				log.Printf("Error creating keep-alive request: %v", err)
				return
			}
			req.Header.Set("Authorization", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Error sending keep-alive request: %v", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("Keep-alive request failed with status code: %d", resp.StatusCode)
			}
		})
		if err != nil {
			log.Printf("Discovery scan failed: %v", err)
			return
		}

		body, err := json.Marshal(items)
		if err != nil {
			log.Printf("Error marshalling scan results: %v", err)
			return
		}

		resultsURL := fmt.Sprintf("%v/api/vulnerability-scans/%d/cves/", h.Config.BackendAPIBaseURL, req.AssetID)
		resultReq, err := http.NewRequest("POST", resultsURL, bytes.NewBuffer(body))
		if err != nil {
			log.Printf("Error creating results request: %v", err)
			return
		}
		resultReq.Header.Set("Content-Type", "application/json")
		resultReq.Header.Set("Authorization", apiKey)

		resp, err := client.Do(resultReq)
		if err != nil {
			log.Printf("Error sending scan results: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to send scan results, status code: %d", resp.StatusCode)
		}
	}(req)

	c.JSON(http.StatusOK, gin.H{"status": "Scan initiated"})
}
