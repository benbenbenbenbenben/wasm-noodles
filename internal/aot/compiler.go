package aot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tetratelabs/wazero"
)

type Options struct {
	InputPath  string
	OutputPath string
	Format     string
	Target     string
}

type Result struct {
	Format          string   `json:"format"`
	Target          string   `json:"target"`
	GOOS            string   `json:"goos"`
	GOARCH          string   `json:"goarch"`
	Engine          string   `json:"engine"`
	FunctionOffsets []uint64 `json:"function_offsets"`
	CodeSize        int      `json:"code_size"`
	OutputSize      int      `json:"output_size"`
	OutputPath      string   `json:"output_path"`
	MetadataPath    string   `json:"metadata_path"`
}

func CompileFile(ctx context.Context, opts Options) (*Result, error) {
	if opts.InputPath == "" {
		return nil, fmt.Errorf("input path is required")
	}
	if opts.OutputPath == "" {
		return nil, fmt.Errorf("output path is required")
	}
	if err := validateFormat(opts.Format); err != nil {
		return nil, err
	}
	if err := validateTarget(opts.Target); err != nil {
		return nil, err
	}

	wasmBytes, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("read wasm module: %w", err)
	}

	compiled, err := compileModule(ctx, wasmBytes)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	artifact, err := buildArtifact(opts.Format, compiled)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(opts.OutputPath, artifact, 0o755); err != nil {
		return nil, fmt.Errorf("write %s artifact: %w", opts.Format, err)
	}

	result := &Result{
		Format:          opts.Format,
		Target:          opts.Target,
		GOOS:            compiled.GOOS,
		GOARCH:          compiled.GOARCH,
		Engine:          compiled.Engine,
		FunctionOffsets: append([]uint64(nil), compiled.FunctionOffsets...),
		CodeSize:        len(compiled.Code),
		OutputSize:      len(artifact),
		OutputPath:      opts.OutputPath,
		MetadataPath:    opts.OutputPath + ".json",
	}

	metadata, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(result.MetadataPath, metadata, 0o644); err != nil {
		return nil, fmt.Errorf("write metadata: %w", err)
	}

	return result, nil
}

func compileModule(ctx context.Context, wasmBytes []byte) (*wazero.CompiledMachineCode, error) {
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	defer r.Close(ctx)

	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("compile wasm module: %w", err)
	}
	defer compiled.Close(ctx)

	machineCode, err := wazero.ExportCompiledMachineCode(compiled)
	if err != nil {
		return nil, fmt.Errorf("export machine code: %w", err)
	}
	if len(machineCode.Code) == 0 {
		return nil, fmt.Errorf("compiled module did not produce native code")
	}
	return machineCode, nil
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	parts := strings.Split(target, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("target must be in <goos>-<goarch> form")
	}
	current := runtime.GOOS + "-" + runtime.GOARCH
	if target != current {
		return fmt.Errorf("target %q is unsupported on this host; build/run on %q to emit matching machine code", target, current)
	}
	return nil
}

func validateFormat(format string) error {
	switch format {
	case "", "raw", "elf":
		return nil
	default:
		return fmt.Errorf("unsupported format %q: want raw or elf", format)
	}
}

func buildArtifact(format string, compiled *wazero.CompiledMachineCode) ([]byte, error) {
	if format == "" || format == "raw" {
		return compiled.Code, nil
	}
	if format == "elf" {
		artifact, err := buildELFObject(compiled)
		if err != nil {
			return nil, fmt.Errorf("build ELF object: %w", err)
		}
		return artifact, nil
	}
	return nil, fmt.Errorf("unsupported format %q", format)
}
