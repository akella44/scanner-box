package models

type TargetType int

const (
	Domain TargetType = iota
	IP
	CIDR
)

type Asset struct {
	Type  TargetType
	Value string
}

type DiscoveryScanRequest struct {
	AssetID string   `json:"asset_id"`
	Targets []string `json:"targets"`
}

type DiscoveryScanOutputItem struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Ports  []int    `json:"ports"`
}
