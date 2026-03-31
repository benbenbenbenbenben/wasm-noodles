package aot

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero"
)

const (
	elfHeaderSize     = 64
	programHeaderSize = 56
	elfPageSize       = 0x1000
	elfBaseVaddr      = 0x400000
	execCtxSize       = 1184
	moduleCtxSize     = 16
)

type programHeader struct {
	typ    uint32
	flags  uint32
	offset uint64
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
	align  uint64
}

type standaloneEntry struct {
	hasResult bool
}

func buildELFExecutable(wasmBytes []byte, compiled *wazero.CompiledMachineCode) ([]byte, error) {
	if compiled.GOOS != "linux" || compiled.GOARCH != "amd64" {
		return nil, fmt.Errorf("standalone ELF executables currently require linux-amd64; got %s-%s", compiled.GOOS, compiled.GOARCH)
	}
	if len(compiled.FunctionOffsets) == 0 {
		return nil, fmt.Errorf("compiled module did not contain any functions")
	}

	entry, err := analyzeStandaloneEntry(wasmBytes)
	if err != nil {
		return nil, err
	}

	textOffset := align(elfHeaderSize+programHeaderSize*2, elfPageSize)
	textVaddr := uint64(elfBaseVaddr + textOffset)

	stub := entryStub(0, 0, 0, entry.hasResult)
	dataOffset := align(textOffset+len(stub)+len(compiled.Code), elfPageSize)
	dataVaddr := uint64(elfBaseVaddr + dataOffset)
	execCtxVaddr := dataVaddr
	moduleCtxVaddr := execCtxVaddr + execCtxSize
	functionVaddr := textVaddr + uint64(len(stub)) + compiled.FunctionOffsets[0]
	stub = entryStub(execCtxVaddr, moduleCtxVaddr, functionVaddr, entry.hasResult)
	text := append(stub, compiled.Code...)

	data := make([]byte, execCtxSize+moduleCtxSize)
	totalSize := dataOffset + len(data)
	out := make([]byte, totalSize)

	copy(out[textOffset:], text)
	copy(out[dataOffset:], data)

	textFileSize := uint64(textOffset + len(text))
	dataFileOffset := uint64(dataOffset)
	dataFileSize := uint64(len(data))

	if err := writeELFHeader(out[:elfHeaderSize], uint16(elf.ET_EXEC), elf.EM_X86_64, uint64(textVaddr), elfHeaderSize, 3); err != nil {
		return nil, err
	}

	headers := []programHeader{
		{
			typ:    uint32(elf.PT_LOAD),
			flags:  uint32(elf.PF_R | elf.PF_X),
			offset: 0,
			vaddr:  elfBaseVaddr,
			paddr:  elfBaseVaddr,
			filesz: textFileSize,
			memsz:  textFileSize,
			align:  elfPageSize,
		},
		{
			typ:    uint32(elf.PT_LOAD),
			flags:  uint32(elf.PF_R | elf.PF_W),
			offset: dataFileOffset,
			vaddr:  dataVaddr,
			paddr:  dataVaddr,
			filesz: dataFileSize,
			memsz:  dataFileSize,
			align:  elfPageSize,
		},
		{
			typ:   uint32(elf.PT_GNU_STACK),
			flags: uint32(elf.PF_R | elf.PF_W),
			align: 16,
		},
	}

	phoff := elfHeaderSize
	for _, header := range headers {
		if err := writeProgramHeader(out[phoff:phoff+programHeaderSize], header); err != nil {
			return nil, err
		}
		phoff += programHeaderSize
	}

	return out, nil
}

func writeELFHeader(dst []byte, typ uint16, machine elf.Machine, entry, phoff uint64, phnum uint16) error {
	if len(dst) < elfHeaderSize {
		return fmt.Errorf("short ELF header buffer")
	}
	copy(dst[:16], []byte{
		0x7f, 'E', 'L', 'F',
		byte(elf.ELFCLASS64),
		byte(elf.ELFDATA2LSB),
		byte(elf.EV_CURRENT),
		byte(elf.ELFOSABI_NONE),
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	binary.LittleEndian.PutUint16(dst[16:18], typ)
	binary.LittleEndian.PutUint16(dst[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(dst[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(dst[24:32], entry)
	binary.LittleEndian.PutUint64(dst[32:40], phoff)
	binary.LittleEndian.PutUint64(dst[40:48], 0)
	binary.LittleEndian.PutUint32(dst[48:52], 0)
	binary.LittleEndian.PutUint16(dst[52:54], elfHeaderSize)
	binary.LittleEndian.PutUint16(dst[54:56], programHeaderSize)
	binary.LittleEndian.PutUint16(dst[56:58], phnum)
	binary.LittleEndian.PutUint16(dst[58:60], 0)
	binary.LittleEndian.PutUint16(dst[60:62], 0)
	binary.LittleEndian.PutUint16(dst[62:64], 0)
	return nil
}

func writeProgramHeader(dst []byte, header programHeader) error {
	if len(dst) < programHeaderSize {
		return fmt.Errorf("short program header buffer")
	}
	binary.LittleEndian.PutUint32(dst[0:4], header.typ)
	binary.LittleEndian.PutUint32(dst[4:8], header.flags)
	binary.LittleEndian.PutUint64(dst[8:16], header.offset)
	binary.LittleEndian.PutUint64(dst[16:24], header.vaddr)
	binary.LittleEndian.PutUint64(dst[24:32], header.paddr)
	binary.LittleEndian.PutUint64(dst[32:40], header.filesz)
	binary.LittleEndian.PutUint64(dst[40:48], header.memsz)
	binary.LittleEndian.PutUint64(dst[48:56], header.align)
	return nil
}

func entryStub(execCtxVaddr, moduleCtxVaddr, functionVaddr uint64, hasResult bool) []byte {
	var out []byte
	out = append(out, 0x48, 0xb9)
	out = appendUint64(out, execCtxVaddr)
	out = append(out, 0x48, 0x89, 0x69, 0x10)
	out = append(out, 0x48, 0x89, 0x61, 0x18)
	out = append(out, 0x48, 0xb8)
	out = appendUint64(out, execCtxVaddr)
	out = append(out, 0x48, 0xbb)
	out = appendUint64(out, moduleCtxVaddr)
	out = append(out, 0x49, 0xbb)
	out = appendUint64(out, functionVaddr)
	out = append(out, 0x41, 0xff, 0xd3)
	out = append(out, 0x48, 0xb9)
	out = appendUint64(out, execCtxVaddr)
	out = append(out, 0x8b, 0x11)
	out = append(out, 0x85, 0xd2)
	out = append(out, 0x75, 0x04)
	if hasResult {
		out = append(out, 0x89, 0xc7)
	} else {
		out = append(out, 0x31, 0xff)
	}
	out = append(out, 0xeb, 0x02)
	out = append(out, 0x89, 0xd7)
	out = append(out, 0xb8, 0x3c, 0x00, 0x00, 0x00)
	out = append(out, 0x0f, 0x05)
	return out
}

func appendUint64(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(dst, buf[:]...)
}

func align(v, boundary int) int {
	if boundary <= 1 {
		return v
	}
	remainder := v % boundary
	if remainder == 0 {
		return v
	}
	return v + boundary - remainder
}

func analyzeStandaloneEntry(wasmBytes []byte) (standaloneEntry, error) {
	parser := wasmParser{data: wasmBytes}
	if err := parser.readHeader(); err != nil {
		return standaloneEntry{}, err
	}

	var (
		types         []wasmFuncType
		functionTypes []uint32
	)
	for !parser.done() {
		sectionID, err := parser.readByte()
		if err != nil {
			return standaloneEntry{}, err
		}
		sectionSize, err := parser.readVarUint32()
		if err != nil {
			return standaloneEntry{}, err
		}
		sectionEnd := parser.offset + int(sectionSize)
		if sectionEnd > len(parser.data) {
			return standaloneEntry{}, fmt.Errorf("malformed wasm module: truncated section %d", sectionID)
		}

		switch sectionID {
		case 1:
			types, err = parser.readTypeSection(sectionEnd)
		case 2:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "imports")
		case 3:
			functionTypes, err = parser.readFunctionSection(sectionEnd)
		case 4:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "tables")
		case 5:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "memories")
		case 6:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "globals")
		case 8:
			err = fmt.Errorf("standalone ELF executables do not support modules with a start function")
		case 9:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "elements")
		case 11:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "data segments")
		case 12:
			err = parser.rejectNonEmptyCountSection(sectionEnd, "data count")
		}
		if err != nil {
			return standaloneEntry{}, err
		}
		parser.offset = sectionEnd
	}

	if len(functionTypes) == 0 {
		return standaloneEntry{}, fmt.Errorf("standalone ELF executable requires at least one defined function")
	}
	typeIndex := functionTypes[0]
	if int(typeIndex) >= len(types) {
		return standaloneEntry{}, fmt.Errorf("malformed wasm module: function type index %d out of range", typeIndex)
	}
	fn := types[typeIndex]
	if fn.paramCount != 0 {
		return standaloneEntry{}, fmt.Errorf("standalone ELF executable requires the first defined function to have no parameters")
	}
	switch len(fn.results) {
	case 0:
		return standaloneEntry{hasResult: false}, nil
	case 1:
		if fn.results[0] != 0x7f && fn.results[0] != 0x7e {
			return standaloneEntry{}, fmt.Errorf("standalone ELF executable requires the first defined function to return i32, i64, or nothing")
		}
		return standaloneEntry{hasResult: true}, nil
	default:
		return standaloneEntry{}, fmt.Errorf("standalone ELF executable requires the first defined function to return at most one value")
	}
}

type wasmFuncType struct {
	paramCount uint32
	results    []byte
}

type wasmParser struct {
	data   []byte
	offset int
}

func (p *wasmParser) done() bool {
	return p.offset >= len(p.data)
}

func (p *wasmParser) readHeader() error {
	if len(p.data) < 8 {
		return fmt.Errorf("malformed wasm module: file too short")
	}
	if string(p.data[:4]) != "\x00asm" {
		return fmt.Errorf("malformed wasm module: invalid magic number")
	}
	if !equalBytes(p.data[4:8], []byte{0x01, 0x00, 0x00, 0x00}) {
		return fmt.Errorf("malformed wasm module: unsupported version")
	}
	p.offset = 8
	return nil
}

func (p *wasmParser) readByte() (byte, error) {
	if p.offset >= len(p.data) {
		return 0, fmt.Errorf("malformed wasm module: unexpected EOF")
	}
	b := p.data[p.offset]
	p.offset++
	return b, nil
}

func (p *wasmParser) readVarUint32() (uint32, error) {
	var (
		result uint32
		shift  uint
	)
	for {
		b, err := p.readByte()
		if err != nil {
			return 0, err
		}
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("malformed wasm module: invalid varuint32")
		}
	}
}

func (p *wasmParser) readTypeSection(sectionEnd int) ([]wasmFuncType, error) {
	count, err := p.readVarUint32()
	if err != nil {
		return nil, err
	}
	types := make([]wasmFuncType, 0, count)
	for i := uint32(0); i < count; i++ {
		form, err := p.readByte()
		if err != nil {
			return nil, err
		}
		if form != 0x60 {
			return nil, fmt.Errorf("malformed wasm module: unsupported type form 0x%x", form)
		}
		paramCount, err := p.readVarUint32()
		if err != nil {
			return nil, err
		}
		for j := uint32(0); j < paramCount; j++ {
			if _, err := p.readByte(); err != nil {
				return nil, err
			}
		}
		resultCount, err := p.readVarUint32()
		if err != nil {
			return nil, err
		}
		results := make([]byte, resultCount)
		for j := uint32(0); j < resultCount; j++ {
			results[j], err = p.readByte()
			if err != nil {
				return nil, err
			}
		}
		types = append(types, wasmFuncType{
			paramCount: paramCount,
			results:    results,
		})
	}
	if p.offset != sectionEnd {
		return nil, fmt.Errorf("malformed wasm module: invalid type section size")
	}
	return types, nil
}

func (p *wasmParser) readFunctionSection(sectionEnd int) ([]uint32, error) {
	count, err := p.readVarUint32()
	if err != nil {
		return nil, err
	}
	functionTypes := make([]uint32, 0, count)
	for i := uint32(0); i < count; i++ {
		typeIndex, err := p.readVarUint32()
		if err != nil {
			return nil, err
		}
		functionTypes = append(functionTypes, typeIndex)
	}
	if p.offset != sectionEnd {
		return nil, fmt.Errorf("malformed wasm module: invalid function section size")
	}
	return functionTypes, nil
}

func (p *wasmParser) rejectNonEmptyCountSection(sectionEnd int, description string) error {
	count, err := p.readVarUint32()
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("standalone ELF executables do not support modules with %s", description)
	}
	if p.offset != sectionEnd {
		return fmt.Errorf("malformed wasm module: invalid %s section size", description)
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
