// sage-close-probe observes the legacy Go API without supplying lifecycle locks.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/session"
)

type observation struct {
	Index     int    `json:"index"`
	Started   int64  `json:"started_ns"`
	Finished  int64  `json:"finished_ns"`
	Verdict   string `json:"verdict"`
	Plaintext string `json:"plaintext_hex"`
}

func core(initiator bool) *session.SecureSession {
	s, err := session.NewSecureSessionFromExporterWithRole("inspector-close-race", bytes.Repeat([]byte{1}, 32), initiator, session.Config{MaxAge: time.Hour, IdleTimeout: 10 * time.Minute, MaxMessages: 1000, RekeyInterval: 256})
	if err != nil {
		panic(err)
	}
	return s
}
func open(s *session.SecureSession, record []byte, index int, origin time.Time) observation {
	r := observation{Index: index, Started: time.Since(origin).Nanoseconds(), Verdict: "REJECT"}
	plain, err := s.DecryptWithAADInbound(record, []byte("sage"))
	r.Finished = time.Since(origin).Nanoseconds()
	if err == nil {
		r.Verdict = "ACCEPT"
		r.Plaintext = hex.EncodeToString(plain)
	}
	return r
}
func emit(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		panic(err)
	}
}
func main() {
	mode := flag.String("mode", "control", "control or race")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "control" && *mode != "race") {
		fmt.Fprintln(os.Stderr, "invalid mode")
		os.Exit(2)
	}
	rounds := 1
	if *mode == "race" {
		rounds = 16
	}
	for _, initiator := range []bool{true, false} {
		direction := "c2s"
		if !initiator {
			direction = "s2c"
		}
		for round := 0; round < rounds; round++ {
			sender := core(initiator)
			records := make([][]byte, 9)
			for i := range records {
				var err error
				records[i], err = sender.EncryptWithAADOutbound([]byte{byte(i + 1)}, []byte("sage"))
				if err != nil {
					panic(err)
				}
			}
			if err := sender.Close(); err != nil {
				panic(err)
			}
			receiver := core(!initiator)
			origin := time.Now()
			// Validate the final unseen record on a separate, active core object.
			fresh := core(!initiator)
			positive := open(fresh, records[8], 8, origin)
			if err := fresh.Close(); err != nil {
				panic(err)
			}
			workers := make([]observation, 8)
			var closing observation
			if *mode == "control" {
				for i := range workers {
					workers[i] = open(receiver, records[i], i, origin)
				}
				closing = observation{Index: 8, Started: time.Since(origin).Nanoseconds(), Verdict: "ACCEPT"}
				if err := receiver.Close(); err != nil {
					closing.Verdict = "REJECT"
				}
				closing.Finished = time.Since(origin).Nanoseconds()
			} else {
				ready := make(chan struct{}, 9)
				start := make(chan struct{})
				var done sync.WaitGroup
				done.Add(9)
				for i := range workers {
					go func(i int) {
						defer done.Done()
						ready <- struct{}{}
						<-start
						workers[i] = open(receiver, records[i], i, origin)
					}(i)
				}
				go func() {
					defer done.Done()
					ready <- struct{}{}
					<-start
					closing = observation{Index: 8, Started: time.Since(origin).Nanoseconds(), Verdict: "ACCEPT"}
					if err := receiver.Close(); err != nil {
						closing.Verdict = "REJECT"
					}
					closing.Finished = time.Since(origin).Nanoseconds()
				}()
				for i := 0; i < 9; i++ {
					<-ready
				}
				close(start)
				done.Wait()
			}
			after := open(receiver, records[8], 8, origin)
			emit(map[string]any{"mode": *mode, "direction": direction, "round": round, "participants": 9, "fresh_control": positive, "workers": workers, "close": closing, "after_close": after})
		}
	}
}
