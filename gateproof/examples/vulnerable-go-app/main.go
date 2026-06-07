package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// Intentionally vulnerable demo code for GateProof/gosec tests.
func runUserCommand() {
	if len(os.Args) < 2 {
		return
	}

	cmd := exec.Command(os.Args[1])
	output, _ := cmd.Output()
	fmt.Println(string(output))
}

func main() {
	runUserCommand()
	_ = http.ListenAndServe(":8080", nil)
}

