package wasm

type CompiledModuleNativeCode struct {
	GOOS            string
	GOARCH          string
	Engine          string
	Code            []byte
	FunctionOffsets []uint64
}
