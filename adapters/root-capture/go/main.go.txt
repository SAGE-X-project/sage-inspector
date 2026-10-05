package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sage-x-project/sage/pkg/agent/guard010"
)

// This inert probe observes only the public root-capture constructor.
func main() {
	if len(os.Args) < 2 || len(os.Args) > 1026 {
		fmt.Println("REJECT")
		return
	}
	items := make([][]byte, 0, len(os.Args)-2)
	for _, encoded := range os.Args[2:] {
		item, err := hex.DecodeString(encoded)
		if err != nil {
			fmt.Println("REJECT")
			return
		}
		items = append(items, item)
	}
	if _, err := guard010.NewRootCapture(items, os.Args[1]); err != nil {
		fmt.Println("REJECT")
		return
	}
	digest, err := guard010.OriginalCommitment(items)
	if err != nil {
		fmt.Println("REJECT")
		return
	}
	fmt.Println("ACCEPT:" + digest)
}
