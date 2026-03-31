package wazero

import (
	"fmt"

	"github.com/tetratelabs/wazero/internal/wasm"
)

type CompiledMachineCode struct {
	GOOS            string
	GOARCH          string
	Engine          string
	Code            []byte
	FunctionOffsets []uint64
}

func ExportCompiledMachineCode(compiled CompiledModule) (*CompiledMachineCode, error) {
	c, ok := compiled.(*compiledModule)
	if !ok {
		return nil, fmt.Errorf("unsupported compiled module implementation %T", compiled)
	}

	exporter, ok := c.compiledEngine.(interface {
		ExportCompiledModule(*wasm.Module) (*wasm.CompiledModuleNativeCode, error)
	})
	if !ok {
		return nil, fmt.Errorf("compiled engine %T does not expose native machine code", c.compiledEngine)
	}

	code, err := exporter.ExportCompiledModule(c.module)
	if err != nil {
		return nil, err
	}

	return &CompiledMachineCode{
		GOOS:            code.GOOS,
		GOARCH:          code.GOARCH,
		Engine:          code.Engine,
		Code:            code.Code,
		FunctionOffsets: code.FunctionOffsets,
	}, nil
}
