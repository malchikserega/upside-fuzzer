package engine

import (
	"testing"
	"time"
)

// Regression test for a real concurrency bug: a bare `chan WebUIStats` shared
// by every /stream SSE handler goroutine does not broadcast -- Go channel
// receive semantics mean concurrent receivers load-balance across sent values,
// so a second connected Web UI client would previously only ever see a
// fraction of the update stream instead of every update. webUIHub fixes this
// by giving each subscriber its own channel and fanning every broadcast out to
// all of them.

func TestWebUIHub_BroadcastReachesEverySubscriber(t *testing.T) {
	hub := newWebUIHub()

	sub1 := hub.subscribe()
	sub2 := hub.subscribe()
	sub3 := hub.subscribe()

	stats := WebUIStats{RequestsPerSec: 42}
	hub.broadcast(stats)

	for i, ch := range []chan WebUIStats{sub1, sub2, sub3} {
		select {
		case got := <-ch:
			if got.RequestsPerSec != 42 {
				t.Errorf("subscriber %d: got RequestsPerSec=%v, want 42", i, got.RequestsPerSec)
			}
		default:
			t.Errorf("subscriber %d never received the broadcast -- this is exactly the bug"+
				" a single shared channel had: only some subscribers get any given update", i)
		}
	}
}

func TestWebUIHub_UnsubscribeStopsFutureBroadcasts(t *testing.T) {
	hub := newWebUIHub()
	sub := hub.subscribe()
	hub.unsubscribe(sub)

	// Broadcasting after unsubscribe must not block (the hub must not still be
	// holding a reference and trying to send into a channel nobody drains) and
	// must not somehow still deliver to the removed subscriber.
	hub.broadcast(WebUIStats{RequestsPerSec: 1})

	select {
	case <-sub:
		t.Error("unsubscribed channel should never receive a later broadcast")
	default:
	}
}

func TestWebUIHub_BroadcastToSlowSubscriberDoesNotBlock(t *testing.T) {
	hub := newWebUIHub()
	sub := hub.subscribe() // buffered size 2, per subscribe()
	_ = sub                // deliberately never drained -- simulates a slow/stuck client

	// Fill the subscriber's buffer, then send a third: broadcast must be
	// non-blocking (drop for a full/slow subscriber) rather than hanging the
	// caller -- the same best-effort semantics the old single-channel
	// `select { case ch <- stats: default: }` pattern had. Bounded with a
	// timeout so a real deadlock fails this one test cleanly instead of
	// hanging the whole suite.
	done := make(chan struct{})
	go func() {
		hub.broadcast(WebUIStats{RequestsPerSec: 1})
		hub.broadcast(WebUIStats{RequestsPerSec: 2})
		hub.broadcast(WebUIStats{RequestsPerSec: 3})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broadcast blocked on a full subscriber buffer instead of dropping non-blockingly")
	}
}
