package utils

import (
	"errors"
	"fmt"
	"log"
	"net"
	"scanner-box/internal/models"
	"strings"
)

func ParseAssets(inputs []string) (map[models.TargetType][]string, error) {
	if len(inputs) == 0 {
		return nil, errors.New("empty input slice")
	}

	assetMap := make(map[models.TargetType][]string)

	for _, input := range inputs {
		trimmed := strings.TrimSpace(input)
		if trimmed == "" {
			continue
		}

		assetType, err := determineAssetType(trimmed)
		if err != nil {
			log.Printf("Warning: %v. String '%s' will be skipped.", err, trimmed)
			continue
		}

		assetMap[assetType] = append(assetMap[assetType], trimmed)
	}

	return assetMap, nil
}

func determineAssetType(value string) (models.TargetType, error) {
	if ip := net.ParseIP(value); ip != nil {
		return models.IP, nil
	}

	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err == nil {
			return models.CIDR, nil
		}
	}

	if isValidDomain(value) {
		return models.Domain, nil
	}

	return -1, fmt.Errorf("unknow asset type %v ", value)
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}
