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
)

func (e EventType) String() string {
	return [...]string{"EventUnkown", "SigStart", "SigReceive", "SigFinish", "SigFailed", "SigTimeout", "DepositReceive", "BlockScanned", "WithdrawRequest", "WithdrawFinalize", "SendOrderBroadcasted"}[e]
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
	subscribers, ok := eb.subscribers[eventType.String()]
	if !ok {
		eb.mu.RUnlock()
		return
	}
	originLen := len(subscribers)
	removeIndexes := make(map[int]bool)
	for i := 0; i < originLen; i++ {
		ch := subscribers[i]
		select {
		case ch <- data:
			// Success
		default:
			// If cannot receive or closed, remove the subscriber
			removeIndexes[i] = true
		}
	}
	eb.mu.RUnlock()

	if len(removeIndexes) > 0 {
		eb.mu.Lock()
		if originLen == len(eb.subscribers[eventType.String()]) {
			var newSubscribers []chan interface{}
			for index, ch := range eb.subscribers[eventType.String()] {
				if _, is := removeIndexes[index]; !is {
					newSubscribers = append(newSubscribers, ch)
				}
			}
			eb.subscribers[eventType.String()] = newSubscribers
		}
		eb.mu.Unlock()
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
