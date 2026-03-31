# wasm-noodles

`wasm-noodles` is a small Go CLI that compiles a `.wasm` module with Wazero's compiler engine and writes out the raw machine-code segment plus a JSON metadata sidecar.

## Usage

```bash
go run ./cmd/wasm-noodles -input ./module.wasm -output ./module.bin -target linux-amd64
```

This writes:

- `module.bin`: raw Wazevo-emitted machine code bytes
- `module.bin.json`: metadata including target and function offsets

At the moment, targets must match the host that runs the CLI because Wazero emits machine code for the current `GOOS/GOARCH`.
