package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/benbenbenbenbenben/wasm-noodles/internal/aot"
)

func main() {
	var (
		input  = flag.String("input", "", "path to the input WebAssembly module")
		output = flag.String("output", "", "path to write the emitted machine code")
		target = flag.String("target", runtime.GOOS+"-"+runtime.GOARCH, "target in <goos>-<goarch> form")
	)
	flag.Parse()

	if *input == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}

	result, err := aot.CompileFile(context.Background(), aot.Options{
		InputPath:  *input,
		OutputPath: *output,
		Target:     *target,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm-noodles: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(
		"wrote %d bytes of %s machine code for %s to %s\nmetadata: %s\n",
		result.CodeSize,
		result.Engine,
		result.Target,
		result.OutputPath,
		result.MetadataPath,
	)
}
