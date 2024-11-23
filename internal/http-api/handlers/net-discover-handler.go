package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"scanner-box/internal/models"
	"scanner-box/internal/runner"

	"github.com/gin-gonic/gin"
)

func HostDiscoveryScanHandler(c *gin.Context) {
	var req models.DiscoveryScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	// Launch scan in a separate goroutine
	go func(req models.DiscoveryScanRequest) {
		// Execute the discovery pipeline
		items, err := runner.RunDiscoverPipline(req.Targets, func() {
			// Send keep-alive signal
			keepAliveURL := fmt.Sprintf("http://0.0.0.0:8000/api/assets/%v/host-scans/keep-alive/", req.AssetID)
			req, err := http.NewRequest("POST", keepAliveURL, nil)
			if err != nil {
				log.Printf("Error creating keep-alive request: %v", err)
				return
			}
			client := &http.Client{}
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

		// Marshal the results into JSON
		body, err := json.Marshal(items)
		if err != nil {
			log.Printf("Error marshalling scan results: %v", err)
			return
		}

		// Send scan results to the backend API
		resultsURL := fmt.Sprintf("http://0.0.0.0:8000/api/assets/%v/host-scans/", req.AssetID)
		resp, err := http.Post(resultsURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("Error sending scan results: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to send scan results, status code: %d", resp.StatusCode)
		}
	}(req)

	// Respond to the HTTP request
	c.JSON(http.StatusOK, gin.H{"status": "Scan initiated"})
}
