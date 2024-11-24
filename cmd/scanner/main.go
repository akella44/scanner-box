package main

import (
	"log"

	"scanner-box/config"
	"scanner-box/internal/handlers"
	"scanner-box/internal/poolmanager"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	err = poolmanager.InitializePool(cfg.PoolSize)
	if err != nil {
		log.Fatalf("Failed to initialize PoolManager: %v", err)
	}
	defer func() {
		pool, err := poolmanager.GetPool()
		if err != nil {
			log.Printf("Error retrieving PoolManager for release: %v", err)
			return
		}
		pool.ReleasePool()
	}()

	h := handlers.NewHostDiscoveryHandler(cfg)
	router := gin.Default()

	scannerGroup := router.Group("/api")
	{
		scannerGroup.POST("/host-discovery-scan", h.HostDiscoveryScanHandler)
		scannerGroup.POST("/vulnerability-scan", h.VulnerabilityScanHandler)
	}

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
