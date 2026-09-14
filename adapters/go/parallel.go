package main

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/session"
)

// The start gate coordinates workers; it does not serialize core calls.
func parallelOpen(core *session.SecureSession, encoded []string, aad []byte) (map[string]any, error) {
	if len(encoded) < 2 || len(encoded) > 16 {
		return nil, fmt.Errorf("parallel worker count must be 2..16")
	}
	records := make([][]byte, len(encoded))
	for i, value := range encoded {
		b, e := hex.DecodeString(value)
		if e != nil || len(b) > 2048 {
			return nil, fmt.Errorf("invalid parallel record")
		}
		records[i] = b
	}
	origin := time.Now()
	ready := make(chan int, len(records))
	start := make(chan struct{})
	workers := make([]map[string]any, len(records))
	var done sync.WaitGroup
	done.Add(len(records))
	for i, record := range records {
		go func(index int, wire []byte) {
			defer done.Done()
			ready <- index
			<-start
			began := time.Since(origin).Nanoseconds()
			plain, e := core.DecryptWithAADInbound(wire, aad)
			ended := time.Since(origin).Nanoseconds()
			result := map[string]any{"index": index, "started_ns": began, "finished_ns": ended, "verdict": "REJECT", "output": map[string]any{}}
			if e == nil {
				result["verdict"] = "ACCEPT"
				result["output"] = map[string]any{"plaintext_hex": hex.EncodeToString(plain)}
			}
			workers[index] = result
		}(i, record)
	}
	observed := map[int]bool{}
	for range records {
		observed[<-ready] = true
	}
	close(start)
	done.Wait()
	return map[string]any{"verdict": "ACCEPT", "output": map[string]any{"start_gate": "all-ready", "workers_ready": len(observed), "workers": workers}}, nil
}
