package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// coverage.go — CoverageReader interface, HTTPCoverageReader (via /shm/ endpoints),
// SHMCoverageReader (direct file-backed SHM for Docker sidecar mode).

type CoverageReader interface {
	Init() error
	GetEdges() (int, error)
	Reset() error
	Capacity() int
	Close() error
}

type HTTPCoverageReader struct {
	client   *http.Client
	shmHost  string
	capacity int
}

func (h *HTTPCoverageReader) Init() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/create", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("/shm/create status=%d body=%s", resp.StatusCode, string(b))
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err == nil {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return nil
}

func (h *HTTPCoverageReader) GetEdges() (int, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(h.shmHost, "/")+"/shm/coverage", nil)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("/shm/coverage status=%d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return 0, err
	}
	if h.capacity <= 0 {
		if sz := toInt(payload["size"]); sz > 0 {
			h.capacity = sz
		}
	}
	return toInt(payload["edges"]), nil
}

func (h *HTTPCoverageReader) Reset() error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.shmHost, "/")+"/shm/reset", nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/shm/reset status=%d", resp.StatusCode)
	}
	return nil
}

func (h *HTTPCoverageReader) Capacity() int { return h.capacity }

func (h *HTTPCoverageReader) Close() error { return nil }

type SHMCoverageReader struct {
	path       string
	size       int
	mode       string
	f          *os.File
	mapSize    int
	mem        []byte
	readBuf    []byte
	activeMode string
	seen       []byte
	zeroBuf    []byte // pre-allocated for Reset() to avoid per-reset allocation
	edges      int
}

func (s *SHMCoverageReader) Init() error {
	desired := maxInt(minSHMBitmapSize, s.size)
	deadline := time.Now().Add(30 * time.Second)
	for {
		fi, err := os.Stat(s.path)
		if err == nil && fi.Size() >= minSHMBitmapSize {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("shm file not ready: %s", s.path)
		}
		time.Sleep(500 * time.Millisecond)
	}
	f, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	mapSize := int(fi.Size())
	if desired > 0 && mapSize > desired {
		mapSize = desired
	}
	if mapSize < minSHMBitmapSize {
		_ = f.Close()
		return fmt.Errorf("shm file too small: %d bytes (need at least %d)", mapSize, minSHMBitmapSize)
	}
	s.f = f
	s.mapSize = mapSize
	s.activeMode = "file"
	if s.shouldUseMmap() {
		mem, err := syscall.Mmap(int(f.Fd()), 0, mapSize, syscall.PROT_READ, syscall.MAP_SHARED)
		if err == nil {
			s.mem = mem
			s.activeMode = "mmap"
		}
	}
	if len(s.mem) == 0 {
		s.readBuf = make([]byte, mapSize)
	}
	s.seen = make([]byte, mapSize)
	s.zeroBuf = make([]byte, mapSize)
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) GetEdges() (int, error) {
	if s.f == nil || s.mapSize <= 0 {
		return 0, errors.New("shm not initialized")
	}
	buf := s.mem
	if len(buf) == 0 {
		if len(s.readBuf) != s.mapSize {
			s.readBuf = make([]byte, s.mapSize)
		}
		n, err := s.f.ReadAt(s.readBuf, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if n <= 0 {
			return s.edges, nil
		}
		buf = s.readBuf[:n]
	}
	if len(s.seen) != len(buf) {
		s.seen = make([]byte, len(buf))
		s.zeroBuf = make([]byte, len(buf))
		s.edges = 0
	}
	// Word-level scan: read 8 bytes at a time as uint64 and skip zero words.
	// Standard AFL optimization — ~8× fewer branches for sparse bitmaps.
	n := len(buf)
	i := 0
	for ; i+8 <= n; i += 8 {
		word := binary.LittleEndian.Uint64(buf[i:])
		seenWord := binary.LittleEndian.Uint64(s.seen[i:])
		newBits := word & ^seenWord
		if newBits == 0 {
			continue
		}
		for j := 0; j < 8; j++ {
			if buf[i+j] != 0 && s.seen[i+j] == 0 {
				s.seen[i+j] = 1
				s.edges++
			}
		}
	}
	// Handle tail bytes.
	for ; i < n; i++ {
		if buf[i] != 0 && s.seen[i] == 0 {
			s.seen[i] = 1
			s.edges++
		}
	}
	return s.edges, nil
}

func (s *SHMCoverageReader) Reset() error {
	if s.f == nil {
		return errors.New("shm not initialized")
	}
	// Zero the actual SHM file so the .NET side starts fresh too.
	if _, err := s.f.WriteAt(s.zeroBuf, 0); err != nil {
		return fmt.Errorf("shm file zero failed: %w", err)
	}
	_ = s.f.Sync()
	if len(s.seen) > 0 {
		for i := range s.seen {
			s.seen[i] = 0
		}
	}
	s.edges = 0
	return nil
}

func (s *SHMCoverageReader) Capacity() int { return s.mapSize }

func (s *SHMCoverageReader) Close() error {
	if len(s.mem) > 0 {
		_ = syscall.Munmap(s.mem)
	}
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

func (s *SHMCoverageReader) shouldUseMmap() bool {
	mode := strings.ToLower(strings.TrimSpace(s.mode))
	switch mode {
	case "mmap":
		return runtime.GOOS == "linux"
	case "auto":
		// Keep auto conservative: mmap only when explicitly allowed.
		return runtime.GOOS == "linux" && strings.TrimSpace(os.Getenv("SMART_FUZZER_SHM_MMAP")) == "1"
	default:
		return false
	}
}

func (s *SHMCoverageReader) ActiveMode() string {
	if strings.TrimSpace(s.activeMode) == "" {
		return "file"
	}
	return s.activeMode
}
