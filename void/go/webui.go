package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

//go:embed webui/index.html
var webuiFS embed.FS

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

		for {
			select {
			case <-ctx.Done():
				return
			case stats := <-f.WebUIStatsCh:
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
