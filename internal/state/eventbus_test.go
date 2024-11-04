package state

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventBus(t *testing.T) {
	bus := NewEventBus()
	t.Log("test eventbus begin")

	testLen := 1000
	exist := make(chan struct{}, testLen)
	wg := sync.WaitGroup{}
	count := atomic.Uint64{}
	for i := 0; i < testLen; i++ {
		unknownCh := make(chan interface{})
		bus.Subscribe(EventUnkown, unknownCh)
		wg.Add(1)
		go func() {
			exist <- struct{}{}
			result := <-unknownCh
			t.Logf("subtest:index = %d, result = %v", i, result)
			count.Add(1)

			wg.Done()
		}()
	}
	<-exist
	bus.Publish(EventUnkown, "OK")
	t.Log("eventbus publish end")
	wg.Wait()
	assert.Equal(t, count.Load(), uint64(len(bus.subscribers[EventUnkown.String()])))
	t.Log("test eventbus end")
}
