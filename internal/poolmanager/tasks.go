package poolmanager

import (
	"scanner-box/internal/models"
	"sync"
)

type VulnerScanTask struct {
	IP              string
	PortCount       int
	ResultCh        chan []models.VulnerScanOutputItem
	ErrCh           chan error
	ProgressHandler func()
	Wg              *sync.WaitGroup
}

func (v VulnerScanTask) TaskType() string {
	return "VulnerabilityScan"
}
