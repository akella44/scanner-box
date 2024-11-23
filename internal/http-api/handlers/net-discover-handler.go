package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"scanner-box/internal/models"
	"scanner-box/internal/runner"

	"github.com/gin-gonic/gin"
)

func HostDiscoveryScanHandler(c *gin.Context) {
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = io.ReadAll(c.Request.Body)
	}

	log.Printf("Request Body: %s", string(bodyBytes))

	var req models.DiscoveryScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	// Launch scan in a separate goroutine
	go func(req models.DiscoveryScanRequest) {
		// Execute the discovery pipeline
		client := &http.Client{}
		jwtToken := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzIiwic3ViIjo0LCJ1c2VybmFtZSI6ImNPRFhnZjR2SWEiLCJhY3RpdmUiOnRydWUsImFkbWluIjp0cnVlLCJleHAiOjIwNDc3MDY4NTIsImlhdCI6MTczMjM0Njg1MiwianRpIjoiNTgxMjQ3MWQtOGI2ZC00MTZkLWI4YTgtZjE5ZTJmNDU3MmY2In0.f9d9RUZ_otMhsrqux3RKJRtEZgjK6kLqE7UsWB5LZGtE7oH6Su2A1JVZqID6kzVdDhHj4H4iH-SA_9Wxc-NSSUDREStNmTsVs9SSQF1__gz3rz_SXUE7bu48qAwvJtLf9TT5klUdDh0lXIGD3DGqSclhl2J9HVKfHPPKzNOeS6SJEijlwGrTy0HwC2itQEnvb3Gv9gyZ8HstvZA4OBt-_POYuc0urJJRE1VY_bNhl5UdZdrlacfw1ksffnmkStxcDmjqxzx-FXCwxnjasYeUDSVvbZgNRoKrlETpNA4OJNsCDGoM0cnMZS21d10xfIB9sLuGsaO9VyjL0cMAzc_-3g"
		items, err := runner.RunDiscoverPipline(req.Targets, func() {
			// Send keep-alive signal
			keepAliveURL := fmt.Sprintf("http://0.0.0.0:8000/api/assets/%d/host-scans/keep-alive/", req.AssetID)
			req, err := http.NewRequest("POST", keepAliveURL, nil)
			if err != nil {
				log.Printf("Error creating keep-alive request: %v", err)
				return
			}
			req.Header.Set("Authorization", jwtToken)
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
		resultsURL := fmt.Sprintf("http://0.0.0.0:8000/api/assets/%d/host-scans/", req.AssetID)
		resultReq, err := http.NewRequest("POST", resultsURL, bytes.NewBuffer(body))
		if err != nil {
			log.Printf("Error creating results request: %v", err)
			return
		}
		resultReq.Header.Set("Content-Type", "application/json")
		resultReq.Header.Set("Authorization", jwtToken)

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

	// Respond to the HTTP request
	c.JSON(http.StatusOK, gin.H{"status": "Scan initiated"})
}
