package scanner

import "sync"

const (
	Init State = iota
	HostDiscovery
	Scan
	Done
	Guard
)

// State 确定内部扫描状态
type State int

type Phase struct {
	sync.RWMutex
	State
}

func (phase *Phase) Is(state State) bool {
	phase.RLock()
	defer phase.RUnlock()

	return phase.State == state
}

func (phase *Phase) Set(state State) {
	phase.Lock()
	defer phase.Unlock()

	phase.State = state
}
