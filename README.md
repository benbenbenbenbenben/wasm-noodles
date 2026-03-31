# wasm-noodles

`wasm-noodles` is a small Go CLI that compiles a `.wasm` module with Wazero's compiler engine and writes either:

- the raw machine-code bytes Wazevo emitted, or
- a minimal linked ELF executable that jumps directly into the first compiled function.

Each output also gets a JSON metadata sidecar.

## Usage

```bash
go run ./cmd/wasm-noodles -input ./module.wasm -output ./module.bin -format raw -target linux-amd64
go run ./cmd/wasm-noodles -input ./module.wasm -output ./module -format elf -target linux-amd64
```

## Output formats

### `-format raw`

Writes the native code bytes exactly as exported from Wazero:

- `module.bin`: raw Wazevo-emitted machine code bytes
- `module.bin.json`: metadata including target and function offsets

This is the closest representation to the compiled code in memory, but it is not self-describing.

### `-format elf`

Writes a minimal linked ELF executable:

- `module`: an `ET_EXEC` ELF64 file for `linux-amd64`
- `module.json`: metadata including target, function offsets, raw code size, and final file size

The executable entry point loads a tiny wazero-compatible execution context, calls the first compiled function, and exits the process with either:

- the function's integer return value, or
- zero when the first function returns no value.

## Current limitations

- Standalone ELF output currently requires `linux-amd64`.
- The executable path currently supports only self-contained modules whose first defined function:
  - has no parameters
  - returns at most one integer result (`i32` or `i64`), or no result
  - does not require memories, tables, globals, imports, element segments, data segments, or a start function
- Targets must match the host that runs the CLI because Wazero emits machine code for the current `GOOS/GOARCH`.
- Raw output still works on any host/target combination that Wazero can compile locally.

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
  "output_size": 4216,
  "output_path": "./module",
  "metadata_path": "./module.json"
}
```

## Development

```bash
go test ./...
go build ./cmd/wasm-noodles
```
