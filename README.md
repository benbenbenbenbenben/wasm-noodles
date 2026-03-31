# wasm-noodles

`wasm-noodles` is a small Go CLI that compiles a `.wasm` module with Wazero's compiler engine and writes either:

- the raw machine-code bytes Wazevo emitted, or
- a minimal ELF relocatable object that wraps those bytes in a standard container.

Each output also gets a JSON metadata sidecar.

## Usage

```bash
go run ./cmd/wasm-noodles -input ./module.wasm -output ./module.bin -format raw -target linux-amd64
go run ./cmd/wasm-noodles -input ./module.wasm -output ./module.o -format elf -target linux-amd64
```

## Output formats

### `-format raw`

Writes the native code bytes exactly as exported from Wazero:

- `module.bin`: raw Wazevo-emitted machine code bytes
- `module.bin.json`: metadata including target and function offsets

This is the closest representation to the compiled code in memory, but it is not self-describing.

### `-format elf`

Writes a minimal ELF relocatable object:

- `module.o`: an `ET_REL` ELF64 file with:
  - a `.text` section containing the emitted machine code
  - a `.symtab` section
  - a `.strtab` section
  - a `.shstrtab` section
- `module.o.json`: metadata including target, function offsets, raw code size, and final file size

Function symbols are currently synthesized as `wasm_function_0`, `wasm_function_1`, and so on, based on Wazero's function offsets.

## Current limitations

- The ELF output is a **relocatable object**, not a fully linked executable.
- The `.text` section contains Wazero-generated machine code, but this project does **not** yet emit relocations, a full runtime shim, or an entry point suitable for direct execution.
- Targets must match the host that runs the CLI because Wazero emits machine code for the current `GOOS/GOARCH`.
- ELF output currently supports the architectures Wazero already emits here and that this wrapper maps to ELF machine types:
  - `amd64`
  - `arm64`

## Metadata example

```json
{
  "format": "elf",
  "target": "linux-amd64",
  "goos": "linux",
  "goarch": "amd64",
  "engine": "wazevo",
  "function_offsets": [0],
  "code_size": 59,
  "output_size": 520,
  "output_path": "./module.o",
  "metadata_path": "./module.o.json"
}
```

## Development

```bash
go test ./...
go build ./cmd/wasm-noodles
```
