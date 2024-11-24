package poolmanager

import (
	"context"
	"fmt"
	"log"
	"scanner-box/internal/core"
	"sync"

	"github.com/panjf2000/ants/v2"
)

type HandlerFunc func(Task)

type PoolManager struct {
	pool         *ants.PoolWithFunc
	handlers     map[string]HandlerFunc
	handlersLock sync.RWMutex
}

var (
	instance *PoolManager
	once     sync.Once
	initErr  error
)

func InitializePool(poolSize int) error {
	once.Do(func() {
		pm := &PoolManager{
			handlers: make(map[string]HandlerFunc),
		}

		dispatcher := func(i interface{}) {
			task, ok := i.(Task)
			if !ok {
				log.Printf("Invalid task type: %T\n", i)
				return
			}

			pm.handlersLock.RLock()
			handler, exists := pm.handlers[task.TaskType()]
			pm.handlersLock.RUnlock()

			if !exists {
				log.Printf("No handler registered for task type: %s\n", task.TaskType())
				return
			}

			handler(task)
		}

		p, err := ants.NewPoolWithFunc(poolSize, dispatcher, ants.WithPanicHandler(func(i interface{}) {
			log.Printf("Pool panicked with input: %v", i)
		}))
		if err != nil {
			initErr = err
			return
		}

		pm.pool = p

		pm.registerHandlers()

		instance = pm
	})
	return initErr
}

func GetPool() (*PoolManager, error) {
	if instance == nil {
		return nil, fmt.Errorf("PoolManager not initialized")
	}
	return instance, nil
}

func (pm *PoolManager) RegisterHandler(taskType string, handler HandlerFunc) {
	pm.handlersLock.Lock()
	defer pm.handlersLock.Unlock()
	pm.handlers[taskType] = handler
}

func (pm *PoolManager) SubmitTask(task Task) error {
	return pm.pool.Invoke(task)
}

func (pm *PoolManager) ReleasePool() {
	if pm.pool != nil {
		pm.pool.Release()
	}
}

func (pm *PoolManager) registerHandlers() {
	pm.RegisterHandler("VulnerabilityScan", pm.vulnerabilityScanHandler)
}

func (pm *PoolManager) vulnerabilityScanHandler(t Task) {
	task, ok := t.(VulnerScanTask)
	if !ok {
		log.Printf("Invalid task type for VulnerabilityScan: %T\n", t)
		return
	}

	scanResults, err := core.VulnerTcpScan(context.Background(), task.IP, task.PortCount, task.ProgressHandler)
	if err != nil {
		task.ErrCh <- fmt.Errorf("scan failed for IP %s: %v", task.IP, err)
		task.Wg.Done()
		return
	}

	task.ResultCh <- scanResults

	if task.ProgressHandler != nil {
		task.ProgressHandler()
	}

	task.Wg.Done()
}
