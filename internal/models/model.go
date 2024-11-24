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
	AssetID int      `json:"asset_id"`
	Targets []string `json:"targets"`
}

type DiscoveryScanOutputItem struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Ports  []int    `json:"ports"`
}

type VulnerScanRequest struct {
	AssetID int      `json:"vulnerability_scan_id"`
	Targets []string `json:"ips"`
}

type Protocol string

const (
	UDP Protocol = "udp"
	TCP Protocol = "tcp"
)

type VulnerScanOutputItem struct {
	IP            string    `json:"ip"`
	Port          uint16    `json:"port"`
	Service       string    `json:"service,omitempty"`
	Protocol      Protocol  `json:"protocol"`
	CPE           string    `json:"cpe,omitempty"`
	CVEidentifier string    `json:"cve_identifier"`
	CVSS          float64   `json:"cvss"`
	Title         string    `json:"title,omitempty"`
	Description   string    `json:"description,omitempty"`
	Exploits      []Exploit `json:"exploits,omitempty"`
}

type Exploit struct {
	CVSS float64 `json:"cvss"`
	Url  string  `json:"url,omitempty"`
}

type NvdApiData struct {
	Vulnerabilities []NvdVulner `json:"vulnerabilities"`
}

type NvdVulner struct {
	CVE NvdCveData `json:"cve"`
}

type NvdCveData struct {
	ID           string     `json:"id"`
	Descriptions []LangData `json:"descriptions"`
}

type LangData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
