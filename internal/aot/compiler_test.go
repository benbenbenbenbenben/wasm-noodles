package aot

import (
	"bytes"
	"context"
	"debug/elf"
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
		Format:     "raw",
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
	if metadata.Format != "raw" {
		t.Fatalf("Format = %q, want raw", metadata.Format)
	}
	if metadata.CodeSize != len(code) {
		t.Fatalf("metadata CodeSize = %d, want %d", metadata.CodeSize, len(code))
	}
	if metadata.OutputSize != len(code) {
		t.Fatalf("metadata OutputSize = %d, want %d", metadata.OutputSize, len(code))
	}
}

func TestCompileFileWritesELFObjectAndMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "module.wasm")
	outputPath := filepath.Join(dir, "module.o")

	if err := os.WriteFile(inputPath, testWasmModule, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	result, err := CompileFile(context.Background(), Options{
		InputPath:  inputPath,
		OutputPath: outputPath,
		Format:     "elf",
		Target:     runtime.GOOS + "-" + runtime.GOARCH,
	})
	if err != nil {
		t.Fatalf("CompileFile() error = %v", err)
	}

	f, err := elf.Open(outputPath)
	if err != nil {
		t.Fatalf("elf.Open() error = %v", err)
	}
	defer f.Close()

	if f.FileHeader.Class != elf.ELFCLASS64 {
		t.Fatalf("ELF class = %v, want ELFCLASS64", f.FileHeader.Class)
	}
	if f.FileHeader.Type != elf.ET_REL {
		t.Fatalf("ELF type = %v, want ET_REL", f.FileHeader.Type)
	}
	if f.Section(".text") == nil {
		t.Fatal("expected .text section")
	}
	if f.Section(".symtab") == nil {
		t.Fatal("expected .symtab section")
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols() error = %v", err)
	}
	found := false
	for _, sym := range symbols {
		if sym.Name == "wasm_function_0" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected symbol wasm_function_0")
	}

	if result.Format != "elf" {
		t.Fatalf("Format = %q, want elf", result.Format)
	}
	if result.CodeSize == 0 {
		t.Fatal("expected non-zero CodeSize")
	}
	if result.OutputSize <= result.CodeSize {
		t.Fatalf("expected ELF file (%d) to be larger than raw code (%d)", result.OutputSize, result.CodeSize)
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

func TestValidateFormatRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	if err := validateFormat("pe"); err == nil {
		t.Fatal("expected unsupported format error")
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
