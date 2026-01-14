package state

import (
	"sync"
)

type EventType int

const (
	BTC_BLOCK_CHAN_LENGTH = 10
)

const (
	EventUnkown EventType = iota
	SigStart
	SigReceive
	SigFinish
	SigFailed
	SigTimeout
	DepositReceive
	BlockScanned
	WithdrawRequest
	WithdrawFinalize
	SendOrderBroadcasted
	NewVoter
	SafeboxTask
	SendOrderRbf
)

func (e EventType) String() string {
	return [...]string{"EventUnkown", "SigStart", "SigReceive", "SigFinish", "SigFailed", "SigTimeout", "DepositReceive",
		"BlockScanned", "WithdrawRequest", "WithdrawFinalize", "SendOrderBroadcasted", "NewVoter", "SafeboxTask", "SendOrderRbf"}[e]
}

type EventBus struct {
	subscribers map[string][]chan interface{}
	mu          sync.RWMutex
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string][]chan interface{}),
	}
}

// enum for eventType
func (eb *EventBus) Subscribe(eventType EventType, ch chan interface{}) {
	if ch == nil {
		panic("channel == nil")
	}
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.subscribers[eventType.String()] = append(eb.subscribers[eventType.String()], ch)
}

func (eb *EventBus) Publish(eventType EventType, data interface{}) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	subscribers, ok := eb.subscribers[eventType.String()]
	if !ok {
		return
	}

	for i := 0; i < len(subscribers); i++ {
		ch := subscribers[i]
		select {
		case ch <- data:
			// Success
		default:
			// If cannot receive or closed, remove the subscriber
			eb.mu.Lock()
			if i < len(eb.subscribers[eventType.String()])-1 {
				eb.subscribers[eventType.String()] = append(eb.subscribers[eventType.String()][:i], eb.subscribers[eventType.String()][i+1:]...)
			} else {
				eb.subscribers[eventType.String()] = eb.subscribers[eventType.String()][:i]
			}
			eb.mu.Unlock()

			if i > 0 {
				i--
			}
		}
	}
}

func (eb *EventBus) Unsubscribe(eventType EventType, ch chan interface{}) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subscribers, ok := eb.subscribers[eventType.String()]
	if !ok {
		return
	}

	for i, subscriber := range subscribers {
		if subscriber == ch {
			if i == len(subscribers)-1 {
				eb.subscribers[eventType.String()] = subscribers[:i]
			} else {
				eb.subscribers[eventType.String()] = append(subscribers[:i], subscribers[i+1:]...)
			}
			break
		}
	}
	if len(eb.subscribers[eventType.String()]) == 0 {
		delete(eb.subscribers, eventType.String())
	}
}
