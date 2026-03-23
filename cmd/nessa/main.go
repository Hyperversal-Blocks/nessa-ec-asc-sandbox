package main

import (
    "fmt"
    "os"
)

// main provides a minimal CLI entrypoint.  It avoids pulling in
// implementation dependencies so that the binary remains lean until
// protocol subcommands are added.
func main() {
    fmt.Fprintln(os.Stdout, "nessa-go: protocol implementation in progress")
}