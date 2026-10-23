// Command privometry-mcp-shim is a placeholder until its milestone lands; see docs/implementation-plan.md.
package main

import (
	"fmt"
	"os"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/buildinfo"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String("privometry-mcp-shim"))
		return
	}
	fmt.Fprintln(os.Stderr, "privometry-mcp-shim: not implemented yet")
	os.Exit(2)
}
