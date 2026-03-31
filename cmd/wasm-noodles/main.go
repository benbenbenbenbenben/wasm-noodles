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
		output = flag.String("output", "", "path to write the emitted artifact")
		format = flag.String("format", "raw", "output format: raw or elf")
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
		Format:     *format,
		Target:     *target,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm-noodles: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(
		"wrote %s artifact (%d code bytes, %d file bytes) with %s machine code for %s to %s\nmetadata: %s\n",
		result.Format,
		result.CodeSize,
		result.OutputSize,
		result.Engine,
		result.Target,
		result.OutputPath,
		result.MetadataPath,
	)
}
