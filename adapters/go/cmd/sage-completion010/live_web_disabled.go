//go:build !liveweb010

package main

import (
	"context"
	"errors"

	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

// The ordinary completion adapter keeps its original pinned-core behavior.
// Live Registry observations are built explicitly with the liveweb010 tag.
type liveWebSource struct{ origin string }

func openLiveWebSource(string) (*liveWebSource, error) {
	return nil, errors.New("live Registry observation is not enabled")
}

func (*liveWebSource) Now() (registry010.Stamp, error) {
	return registry010.Stamp{}, errors.New("live Registry observation is not enabled")
}

func (*liveWebSource) Read(context.Context, string) (registry010.Snapshot, error) {
	return registry010.Snapshot{}, errors.New("live Registry observation is not enabled")
}
