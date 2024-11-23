package main

import (
	"log"

	handlers "scanner-box/internal/http-api/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	scannerGroup := router.Group("/api")
	{
		scannerGroup.POST("/host-discovery-scan", handlers.HostDiscoveryScanHandler)
	}

	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
