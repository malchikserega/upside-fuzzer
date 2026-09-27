package engine

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

//go:embed webui/index.html
var webuiFS embed.FS

// webUIHub fans a WebUIStats update out to every currently-connected /stream
// client. A plain Go channel cannot do this: multiple goroutines receiving from
// one channel load-balance across the payloads (each update goes to exactly one
// receiver), they don't broadcast -- so with a bare shared channel, opening a
// second Web UI browser tab silently made both tabs each see only a fraction of
// the update stream instead of the full one. Each subscriber gets its own
// buffered channel; broadcast is non-blocking per-subscriber (drops that one
// update for a slow/stuck subscriber rather than blocking the fuzzer's stats
// loop on it), matching the previous single-channel's best-effort semantics.
type webUIHub struct {
	mu   sync.Mutex
	subs map[chan WebUIStats]struct{}
}

func newWebUIHub() *webUIHub {
	return &webUIHub{subs: make(map[chan WebUIStats]struct{})}
}

func (h *webUIHub) subscribe() chan WebUIStats {
	ch := make(chan WebUIStats, 2)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *webUIHub) unsubscribe(ch chan WebUIStats) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *webUIHub) broadcast(stats WebUIStats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- stats:
		default:
		}
	}
}

// RunWebUI starts the HTTP server that hosts the Web UI and the SSE stream.
func RunWebUI(f *Fuzzer) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		html, err := webuiFS.ReadFile("webui/index.html")
		if err != nil {
			http.Error(w, "Could not read index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(html)
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		ch := f.WebUIHub.subscribe()
		defer f.WebUIHub.unsubscribe(ch)

		for {
			select {
			case <-ctx.Done():
				return
			case stats := <-ch:
				data, err := json.Marshal(stats)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-ticker.C:
				// Send an empty comment to keep connection alive
				fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()
			}
		}
	})

	port := f.cfg.WebUIPort
	if port <= 0 {
		port = 13377
	}
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	fmt.Printf("Web UI available at http://%s\n", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Web UI server error: %v\n", err)
	}
}
