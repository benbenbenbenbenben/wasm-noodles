package aot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCompileFileWritesRawMachineCodeAndMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "module.wasm")
	outputPath := filepath.Join(dir, "module.bin")

	if err := os.WriteFile(inputPath, testWasmModule, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	result, err := CompileFile(context.Background(), Options{
		InputPath:  inputPath,
		OutputPath: outputPath,
		Target:     runtime.GOOS + "-" + runtime.GOARCH,
	})
	if err != nil {
		t.Fatalf("CompileFile() error = %v", err)
	}

	code, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if len(code) == 0 {
		t.Fatal("expected non-empty machine code")
	}
	if bytes.HasPrefix(code, []byte("WAZEVO")) {
		t.Fatal("expected raw machine code, not the wazero cache header")
	}
	if result.CodeSize != len(code) {
		t.Fatalf("CodeSize = %d, want %d", result.CodeSize, len(code))
	}
	if len(result.FunctionOffsets) != 1 {
		t.Fatalf("FunctionOffsets length = %d, want 1", len(result.FunctionOffsets))
	}

	metadataBytes, err := os.ReadFile(result.MetadataPath)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}

	var metadata Result
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata.Target != runtime.GOOS+"-"+runtime.GOARCH {
		t.Fatalf("Target = %q", metadata.Target)
	}
	if metadata.CodeSize != len(code) {
		t.Fatalf("metadata CodeSize = %d, want %d", metadata.CodeSize, len(code))
	}
}

func TestValidateTargetRejectsCrossTargetRequests(t *testing.T) {
	t.Parallel()

	target := "linux-amd64"
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		target = "linux-arm64"
	}

	if err := validateTarget(target); err == nil {
		t.Fatal("expected cross-target validation error")
	}
}

var testWasmModule = []byte{
	0x00, 0x61, 0x73, 0x6d,
	0x01, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
	0x03, 0x02, 0x01, 0x00,
	0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
	0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
}
