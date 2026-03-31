package aot

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero"
)

type elfSection struct {
	name      uint32
	typ       uint32
	flags     uint64
	addr      uint64
	offset    uint64
	size      uint64
	link      uint32
	info      uint32
	addralign uint64
	entsize   uint64
}

type elfSymbol struct {
	name  uint32
	info  byte
	other byte
	shndx uint16
	value uint64
	size  uint64
}

func buildELFObject(compiled *wazero.CompiledMachineCode) ([]byte, error) {
	machine, err := elfMachine(compiled.GOARCH)
	if err != nil {
		return nil, err
	}

	text := compiled.Code
	if len(text) == 0 {
		return nil, fmt.Errorf("empty machine code")
	}

	strtab := newStringTable()
	symbols := make([]elfSymbol, 0, len(compiled.FunctionOffsets)+2)
	symbols = append(symbols, elfSymbol{})
	symbols = append(symbols, elfSymbol{
		info:  byte(elf.STB_LOCAL<<4) | byte(elf.STT_SECTION),
		shndx: 1,
	})
	for i, offset := range compiled.FunctionOffsets {
		symbols = append(symbols, elfSymbol{
			name:  strtab.add(fmt.Sprintf("wasm_function_%d", i)),
			info:  byte(elf.STB_GLOBAL<<4) | byte(elf.STT_FUNC),
			shndx: 1,
			value: offset,
		})
	}

	symtab := make([]byte, 0, len(symbols)*24)
	for i, sym := range symbols {
		size := uint64(0)
		if i >= 2 {
			fnIndex := i - 2
			start := compiled.FunctionOffsets[fnIndex]
			end := uint64(len(text))
			if fnIndex+1 < len(compiled.FunctionOffsets) {
				end = compiled.FunctionOffsets[fnIndex+1]
			}
			size = end - start
		}

		var entry [24]byte
		binary.LittleEndian.PutUint32(entry[0:4], sym.name)
		entry[4] = sym.info
		entry[5] = sym.other
		binary.LittleEndian.PutUint16(entry[6:8], sym.shndx)
		binary.LittleEndian.PutUint64(entry[8:16], sym.value)
		binary.LittleEndian.PutUint64(entry[16:24], size)
		symtab = append(symtab, entry[:]...)
	}

	shstrtab := newStringTable()
	textName := shstrtab.add(".text")
	symtabName := shstrtab.add(".symtab")
	strtabName := shstrtab.add(".strtab")
	shstrtabName := shstrtab.add(".shstrtab")

	const (
		elfHeaderSize     = 64
		sectionHeaderSize = 64
	)

	textOffset := align(elfHeaderSize, 16)
	symtabOffset := align(textOffset+len(text), 8)
	strtabOffset := symtabOffset + len(symtab)
	shstrtabOffset := strtabOffset + len(strtab.bytes())
	sectionTableOffset := align(shstrtabOffset+len(shstrtab.bytes()), 8)

	sections := []elfSection{
		{},
		{
			name:      textName,
			typ:       uint32(elf.SHT_PROGBITS),
			flags:     uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR),
			offset:    uint64(textOffset),
			size:      uint64(len(text)),
			addralign: 16,
		},
		{
			name:      symtabName,
			typ:       uint32(elf.SHT_SYMTAB),
			offset:    uint64(symtabOffset),
			size:      uint64(len(symtab)),
			link:      3,
			info:      2,
			addralign: 8,
			entsize:   24,
		},
		{
			name:      strtabName,
			typ:       uint32(elf.SHT_STRTAB),
			offset:    uint64(strtabOffset),
			size:      uint64(len(strtab.bytes())),
			addralign: 1,
		},
		{
			name:      shstrtabName,
			typ:       uint32(elf.SHT_STRTAB),
			offset:    uint64(shstrtabOffset),
			size:      uint64(len(shstrtab.bytes())),
			addralign: 1,
		},
	}

	totalSize := sectionTableOffset + sectionHeaderSize*len(sections)
	out := make([]byte, totalSize)

	copy(out[textOffset:], text)
	copy(out[symtabOffset:], symtab)
	copy(out[strtabOffset:], strtab.bytes())
	copy(out[shstrtabOffset:], shstrtab.bytes())

	if err := writeELFHeader(out[:elfHeaderSize], machine, uint64(sectionTableOffset), uint16(len(sections))); err != nil {
		return nil, err
	}

	shoff := sectionTableOffset
	for _, section := range sections {
		if err := writeSectionHeader(out[shoff:shoff+sectionHeaderSize], section); err != nil {
			return nil, err
		}
		shoff += sectionHeaderSize
	}

	return out, nil
}

func writeELFHeader(dst []byte, machine elf.Machine, shoff uint64, shnum uint16) error {
	if len(dst) < 64 {
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
	binary.LittleEndian.PutUint16(dst[16:18], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(dst[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(dst[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(dst[24:32], 0)
	binary.LittleEndian.PutUint64(dst[32:40], 0)
	binary.LittleEndian.PutUint64(dst[40:48], shoff)
	binary.LittleEndian.PutUint32(dst[48:52], 0)
	binary.LittleEndian.PutUint16(dst[52:54], 64)
	binary.LittleEndian.PutUint16(dst[54:56], 0)
	binary.LittleEndian.PutUint16(dst[56:58], 0)
	binary.LittleEndian.PutUint16(dst[58:60], 64)
	binary.LittleEndian.PutUint16(dst[60:62], shnum)
	binary.LittleEndian.PutUint16(dst[62:64], 4)
	return nil
}

func writeSectionHeader(dst []byte, section elfSection) error {
	if len(dst) < 64 {
		return fmt.Errorf("short section header buffer")
	}
	binary.LittleEndian.PutUint32(dst[0:4], section.name)
	binary.LittleEndian.PutUint32(dst[4:8], section.typ)
	binary.LittleEndian.PutUint64(dst[8:16], section.flags)
	binary.LittleEndian.PutUint64(dst[16:24], section.addr)
	binary.LittleEndian.PutUint64(dst[24:32], section.offset)
	binary.LittleEndian.PutUint64(dst[32:40], section.size)
	binary.LittleEndian.PutUint32(dst[40:44], section.link)
	binary.LittleEndian.PutUint32(dst[44:48], section.info)
	binary.LittleEndian.PutUint64(dst[48:56], section.addralign)
	binary.LittleEndian.PutUint64(dst[56:64], section.entsize)
	return nil
}

func elfMachine(goarch string) (elf.Machine, error) {
	switch goarch {
	case "amd64":
		return elf.EM_X86_64, nil
	case "arm64":
		return elf.EM_AARCH64, nil
	default:
		return 0, fmt.Errorf("unsupported GOARCH %q for ELF output", goarch)
	}
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

type stringTable struct {
	buf bytes.Buffer
}

func newStringTable() *stringTable {
	st := &stringTable{}
	st.buf.WriteByte(0)
	return st
}

func (s *stringTable) add(name string) uint32 {
	offset := uint32(s.buf.Len())
	s.buf.WriteString(name)
	s.buf.WriteByte(0)
	return offset
}

func (s *stringTable) bytes() []byte {
	return s.buf.Bytes()
}
