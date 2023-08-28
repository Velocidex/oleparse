package oleparse

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

const (
	FREESECT      = 0xFFFFFFFF
	ENDOFCHAIN    = 0xFFFFFFFE
	OLE_SIGNATURE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

	MODULE_EXTENSION = "bas"
	CLASS_EXTENSION  = "cls"
	FORM_EXTENSION   = "frm"
)

var (
	MAC_CODEPAGES = map[uint16]string{}
	BINFILE_NAME  = regexp.MustCompile("(?i).bin$")
)

type OLEHeader struct {
	AbSig [8]byte
	Clid  [16]byte

	MinorVersion    uint16
	DllVersion      uint16
	ByteOrder       uint16
	SectorShift     uint16
	MiniSectorShift uint16
	Reserved        uint16

	Reserved1        uint32
	Reserved2        uint32
	CsectFat         uint32
	SectDirStart     uint32
	Signature        uint32
	MiniSectorCutoff uint32
	SectMiniFatStart uint32
	CsectMiniFat     uint32
	SectDifStart     uint32
	CsectDif         uint32

	SectFat [109]uint32
}

type DirectoryHeader struct {
	AB          [32]uint16
	CB          uint16
	Mse         byte
	Flags       byte
	SidLeftSib  uint32
	SidRightSib uint32
	SidChild    uint32
	ClsId       [16]byte
	UserFlags   uint32
	CreateTime  uint64
	ModifyTime  uint64
	SectStart   uint32
	Size        uint32
	PropType    uint16
}

type Directory struct {
	Header DirectoryHeader
	Index  uint32
	Name   string
	data   []byte
}

func NewDirectory(data []byte, index uint32) (*Directory, error) {
	self := &Directory{data: data, Index: index}

	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.LittleEndian, &self.Header)
	if err != nil {
		return nil, err
	}

	self.Name = strings.TrimRight(
		string(utf16.Decode(self.Header.AB[:])), "\x00")

	return self, nil
}

type OLEFile struct {
	data           []byte
	ministream     []byte
	Header         OLEHeader
	SectorSize     int
	MiniSectorSize int
	SectorCount    int
	FatSectors     []uint32
	Fat            []uint32
	MiniFat        []uint32
	Directory      []*Directory
}

type VBAModule struct {
	Code       string
	ModuleName string
	StreamName string
	Type       string
}

func (self *OLEFile) ReadSector(sector uint32) []byte {
	start := 512 + self.SectorSize*int(sector)

	to_read := self.SectorSize
	if start > len(self.data) {
		return nil
	}

	if start+to_read >= len(self.data) {
		to_read = len(self.data) - start
	}
	return self.data[start : start+to_read]
}

func (self *OLEFile) ReadMiniSector(sector uint32) []byte {
	start := self.MiniSectorSize * int(sector)

	to_read := self.MiniSectorSize
	if start > len(self.ministream) {
		return nil
	}

	if start+to_read >= len(self.ministream) {
		to_read = len(self.ministream) - start
	}

	return self.ministream[start : start+to_read]
}

func (self *OLEFile) ReadFat(sector uint32) uint32 {
	if int(sector) >= len(self.Fat) {
		return 0
	}
	return self.Fat[sector]
}

func (self *OLEFile) ReadMiniFat(sector uint32) uint32 {
	if int(sector) >= len(self.MiniFat) {
		return 0
	}
	return self.MiniFat[sector]
}

func (self *OLEFile) ReadChain(start uint32) []byte {
	return self._ReadChain(start, self.ReadSector, self.ReadFat)
}

func (self *OLEFile) ReadMiniChain(start uint32) []byte {
	return self._ReadChain(start, self.ReadMiniSector, self.ReadMiniFat)
}

func (self *OLEFile) _ReadChain(
	start uint32,
	ReadSector func(uint32) []byte,
	ReadFat func(sector uint32) uint32) []byte {
	check := make(map[uint32]bool)
	result := []byte{}

	for sector := start; sector != ENDOFCHAIN; {
		result = append(result, ReadSector(sector)...)
		next := ReadFat(sector)
		_, pres := check[next]
		if pres {
			fmt.Printf("infinite loop detected at %v to %v starting at %v",
				sector, next, start)
			return result
		}
		check[next] = true
		sector = next
	}
	return result
}

func (self *OLEFile) GetStream(index uint32) []byte {
	if int(index) >= len(self.Directory) {
		return nil
	}

	var data []byte

	d := self.Directory[index]
	if d.Header.Size < self.Header.MiniSectorCutoff {
		data = self.ReadMiniChain(d.Header.SectStart)
	} else {
		data = self.ReadChain(d.Header.SectStart)
	}

	return data[:uint32_min(d.Header.Size, uint32(len(data)))]
}

func (self *OLEFile) FindStreamByName(name string) *Directory {
	for _, d := range self.Directory {
		if d.Name == name {
			return d
		}
	}

	return nil
}

func (self *OLEFile) OpenStreamByName(name string) ([]byte, error) {
	d := self.FindStreamByName(name)
	if d == nil {
		return nil, errors.New("Not found")
	}

	return self.GetStream(d.Index), nil
}

func NewOLEFile(data []byte) (*OLEFile, error) {
	if len(data) < 8 ||
		string(data[:8]) != OLE_SIGNATURE {
		return nil, errors.New("Invalid signature")
	}

	self := OLEFile{data: data}
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.LittleEndian, &self.Header)
	if err != nil {
		return nil, err
	}

	if self.Header.SectorShift > MAX_SECTOR_SHIFT {
		return nil, fmt.Errorf(
			"Sector size too large: %v", self.Header.SectorShift)
	}

	self.SectorSize = 1 << self.Header.SectorShift
	if self.SectorSize < 8 {
		return nil, fmt.Errorf(
			"Sector size too small: %v", self.SectorSize)
	}

	self.MiniSectorSize = 1 << self.Header.MiniSectorShift
	if (len(data)-512)%self.SectorSize != 0 {
		DebugPrintf("Last sector has invalid size\n")
	}

	self.SectorCount = (len(data) - 512) / self.SectorSize
	for _, sect := range self.Header.SectFat {
		if sect != FREESECT {
			self.FatSectors = append(self.FatSectors, sect)
		}
	}

	// load any DIF sectors
	sector := self.Header.SectDifStart
	seen := make(map[uint32]bool)
	for sector != FREESECT && sector != ENDOFCHAIN {
		data := self.ReadSector(sector)
		dif_values := make([]uint32, self.SectorSize/4)
		buffer := bytes.NewBuffer(data)
		err := binary.Read(buffer, binary.LittleEndian, dif_values)
		if err != nil {
			return nil, err
		}

		// the last entry is actually a pointer to next DIF
		if len(dif_values) < 2 {
			return nil, fmt.Errorf("infinite loop detected")
		}

		next := dif_values[len(dif_values)-1]
		for _, value := range dif_values[:len(dif_values)-2] {
			if value != FREESECT {
				self.FatSectors = append(self.FatSectors, value)
			}
		}

		_, pres := seen[next]
		if pres || len(seen) > MAX_SECTORS {
			return nil, fmt.Errorf(
				"infinite loop detected at %v to %v starting at DIF",
				sector, next)
		}

		seen[next] = true
		sector = next
	}

	// load the FAT
	for _, fat_sect := range self.FatSectors {
		sect_data := self.ReadSector(fat_sect)

		sect_longs := make([]uint32, self.SectorSize/4)
		buffer := bytes.NewBuffer(sect_data)
		err := binary.Read(buffer, binary.LittleEndian, sect_longs)
		if err != nil {
			return nil, err
		}

		self.Fat = append(self.Fat, sect_longs...)
	}

	// get the list of directory sectors
	dir_buffer := self.ReadChain(self.Header.SectDirStart)
	for directory_index := 0; directory_index*128 < len(dir_buffer); directory_index += 1 {
		dir_obj, err := NewDirectory(
			dir_buffer[min(directory_index*128, len(dir_buffer)):],
			uint32(directory_index))
		if err != nil {
			return nil, err
		}
		self.Directory = append(self.Directory, dir_obj)
	}

	if len(self.Directory) == 0 {
		return nil, errors.New("Directory not found")
	}

	// load the ministream
	root_directory := self.Directory[0]
	if root_directory.Header.SectStart != ENDOFCHAIN {
		self.ministream = self.ReadChain(root_directory.Header.SectStart)
		if len(self.ministream) < int(root_directory.Header.Size) {
			return nil, fmt.Errorf(
				"specified size is larger than actual stream length %v\n",
				len(self.ministream))
		}

		self.ministream = self.ministream[:uint32_min(
			root_directory.Header.Size, uint32(len(self.ministream)))]

		data := self.ReadChain(self.Header.SectMiniFatStart)
		for i := 0; i < len(data); i += self.SectorSize {
			if i+self.SectorSize > len(data) {
				DebugPrintf("encountered EOF while parsing minifat\n")
				break
			}
			chunk_data := data[i:min(i+self.SectorSize, len(data))]
			chunk := make([]uint32, self.SectorSize/4)
			buffer := bytes.NewBuffer(chunk_data)
			err := binary.Read(buffer, binary.LittleEndian, &chunk)
			if err != nil {
				return nil, err
			}

			self.MiniFat = append(self.MiniFat, chunk...)
		}

	}

	// 2.3 The locations for MiniFat sectors are stored in a standard
	// chain in the Fat, with the beginning of the chain stored in the
	// header.

	return &self, nil
}

func DecompressStream(compressed_container []byte) []byte {
	// MS-OVBA
	// 2.4.1.2
	var decompressed_container []byte
	compressed_current := 0
	//	compressed_chunk_start := 0
	decompressed_chunk_start := 0

	sig_byte := compressed_container[compressed_current]
	if sig_byte != 0x01 {
		fmt.Printf("invalid signature byte %02X", sig_byte)
		return nil
	}

	compressed_current += 1

	for compressed_current < len(compressed_container) {
		// 2.4.1.1.5
		//compressed_chunk_start = compressed_current
		compressed_chunk_header := binary.LittleEndian.Uint16(
			compressed_container[compressed_current:])

		// chunk_sign = compressed_chunk_header & 0b0000000000001110
		chunk_size := (compressed_chunk_header & 0x0FFF) + 3
		// 1 == compressed, 0 == uncompressed
		chunk_is_compressed := (compressed_chunk_header & 0x8000) >> 15

		if chunk_is_compressed != 0 && chunk_size > 4095 {
			DebugPrintf("CompressedChunkSize > 4095 but CompressedChunkFlag == 1")
		}
		if chunk_is_compressed == 0 && chunk_size != 4095 {
			DebugPrintf("CompressedChunkSize != 4095 but CompressedChunkFlag == 0")
		}

		DebugPrintf("chunk size = %v", chunk_size)

		compressed_end := len(compressed_container)
		if compressed_end > compressed_current+int(chunk_size) {
			compressed_end = compressed_current + int(chunk_size)
		}

		compressed_current += 2

		if chunk_is_compressed == 0 { // uncompressed
			decompressed_container = append(decompressed_container,
				compressed_container[compressed_current:compressed_current+4096]...)
			compressed_current += 4096
			continue
		}

		decompressed_chunk_start = len(decompressed_container)
		for compressed_current < compressed_end {
			flag_byte := compressed_container[compressed_current]
			compressed_current += 1
			for bit_index := uint16(0); bit_index < 8; bit_index++ {
				if compressed_current >= compressed_end {
					break
				}

				if (1<<bit_index)&flag_byte == 0 { // LiteralToken
					decompressed_container = append(decompressed_container,
						compressed_container[compressed_current])
					compressed_current += 1
					continue
				}

				// copy tokens
				copy_token := binary.LittleEndian.Uint16(
					compressed_container[compressed_current:])

				length_mask, offset_mask, bit_count, maximum_length := copytoken_help(
					len(decompressed_container) - decompressed_chunk_start)
				_ = maximum_length

				length := (int(copy_token) & length_mask) + 3
				temp1 := int(copy_token) & offset_mask
				temp2 := 16 - bit_count
				offset := (temp1 >> temp2) + 1
				copy_source := len(decompressed_container) - int(offset)
				DebugPrintf("copy_source %v %v", copy_source, length)

				for index := copy_source; index < copy_source+int(length); index++ {
					DebugPrintf("len %v idx %v", len(decompressed_container), index)
					if index < 0 || index > len(decompressed_container) {
						DebugPrintf("Decompression out of bound %v (container length %v)",
							index, len(decompressed_container))
						return decompressed_container
					}

					decompressed_container = append(decompressed_container,
						decompressed_container[index])
				}
				compressed_current += 2
			}
		}
	}

	return decompressed_container
}

func copytoken_help(difference int) (int, int, uint32, int) {
	// Original code used math.Log() and math.Ceil() but these are
	// slow so this code is refactored to use integer arithmic.
	bit_count := uint32(0)
	j := difference
	for 1<<bit_count < j {
		bit_count += 1
	}

	if bit_count < 4 {
		bit_count = 4
	}
	length_mask := int(uint16(0xFFFF) >> bit_count)
	offset_mask := ^length_mask
	maximum_length := int(0xFFFF>>bit_count) + 3

	return length_mask, offset_mask, bit_count, maximum_length
}

func getUint16(dir_stream []byte, offset *int) uint16 {
	if len(dir_stream) < *offset+2 {
		return 0
	}

	result := binary.LittleEndian.Uint16(dir_stream[*offset:])
	*offset += 2
	return result
}

func getUint32(dir_stream []byte, offset *int) uint32 {
	if len(dir_stream) < *offset+4 {
		return 0
	}

	result := binary.LittleEndian.Uint32(dir_stream[*offset:])
	*offset += 4
	return result
}

func ExtractMacros(ofdoc *OLEFile) ([]*VBAModule, error) {
	var result []*VBAModule

	project := ofdoc.FindStreamByName("PROJECT")
	if project == nil {
		return nil, errors.New("missing PROJECT stream")
	}

	project_data := ofdoc.GetStream(project.Index)
	re_keyval := regexp.MustCompile("^([^=]+)=(.*)$")
	code_modules := make(map[string]string)
	for _, line := range strings.Split(string(project_data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 1 {
			break
		}

		if strings.HasPrefix(line, "[") {
			continue
		}

		m := re_keyval.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		switch m[1] {
		case "Document":
			key := strings.Split(m[2], "/")[0]
			code_modules[key] = CLASS_EXTENSION
		case "Module":
			code_modules[m[2]] = MODULE_EXTENSION
		case "BaseClass":
			code_modules[m[2]] = FORM_EXTENSION
		}
	}

	dir_stream_obj := ofdoc.FindStreamByName("dir")
	if dir_stream_obj == nil {
		return nil, errors.New("missing dir stream")
	}

	dir_stream := DecompressStream(ofdoc.GetStream(dir_stream_obj.Index))
	check_value := func(name string, expected uint32, value uint32) {
		DebugPrintf("%s: %v", name, expected)
		if expected != value {
			DebugPrintf("invalid value for %v expected %04x got %04x",
				name, expected, value)
		}
	}

	i := 0

	// PROJECTSYSKIND Record
	projectsyskind_id := getUint16(dir_stream, &i)
	check_value("PROJECTSYSKIND_Id", 0x0001, uint32(projectsyskind_id))

	projectsyskind_size := getUint32(dir_stream, &i)
	check_value("PROJECTSYSKIND_Size", 0x0004, projectsyskind_size)

	projectsyskind_syskind := getUint32(dir_stream, &i)
	if projectsyskind_syskind == 0x00 {
		DebugPrintf("16-bit Windows")
	} else if projectsyskind_syskind == 0x01 {
		DebugPrintf("32-bit Windows")
	} else if projectsyskind_syskind == 0x02 {
		DebugPrintf("Macintosh")
	} else if projectsyskind_syskind == 0x03 {
		DebugPrintf("64-bit Windows")
	} else {
		return nil, fmt.Errorf(
			"invalid PROJECTSYSKIND_SysKind %04x", projectsyskind_syskind)
	}

	// Optional: CompatVersionRecord
	compatversion_id := getUint16(dir_stream, &i)
	if compatversion_id == 0x4A {
		compatversion_size := getUint32(dir_stream, &i)
		check_value("PROJECTCOMPATVERSION_Size", 0x4, compatversion_size)
		i += 4 // Skip ProjectCompatVersion
	} else {
		i -= 2 // No CompatVersionRecord present - undo read of the ID
	}

	// PROJECTLCID Record
	projectlcid_id := getUint16(dir_stream, &i)

	check_value("PROJECTLCID_Id", 0x0002, uint32(projectlcid_id))
	projectlcid_size := getUint32(dir_stream, &i)
	check_value("PROJECTLCID_Size", 0x0004, projectlcid_size)

	projectlcid_lcid := getUint32(dir_stream, &i)
	check_value("PROJECTLCID_Lcid", 0x409, projectlcid_lcid)

	// PROJECTLCIDINVOKE Record
	projectlcidinvoke_id := getUint16(dir_stream, &i)
	check_value("PROJECTLCIDINVOKE_Id", 0x0014, uint32(projectlcidinvoke_id))
	projectlcidinvoke_size := getUint32(dir_stream, &i)
	check_value("PROJECTLCIDINVOKE_Size", 0x0004, projectlcidinvoke_size)
	projectlcidinvoke_lcidinvoke := getUint32(dir_stream, &i)
	check_value("PROJECTLCIDINVOKE_LcidInvoke", 0x409, projectlcidinvoke_lcidinvoke)

	// PROJECTCODEPAGE Record
	projectcodepage_id := getUint16(dir_stream, &i)
	check_value("PROJECTCODEPAGE_Id", 0x0003, uint32(projectcodepage_id))
	projectcodepage_size := getUint32(dir_stream, &i)
	check_value("PROJECTCODEPAGE_Size", 0x0002, projectcodepage_size)
	projectcodepage_codepage := getUint16(dir_stream, &i)

	// PROJECTNAME Record
	projectname_id := getUint16(dir_stream, &i)
	check_value("PROJECTNAME_Id", 0x0004, uint32(projectname_id))
	projectname_sizeof_projectname := int(getUint32(dir_stream, &i))
	if projectname_sizeof_projectname < 1 || projectname_sizeof_projectname > 128 {
		return nil, errors.New(fmt.Sprintf(
			"PROJECTNAME_SizeOfProjectName value not in range: %v",
			projectname_sizeof_projectname))
	}

	// projectname_projectname := dir_stream[i : i+projectname_sizeof_projectname]
	i += projectname_sizeof_projectname

	// PROJECTDOCSTRING Record
	projectdocstring_id := getUint16(dir_stream, &i)
	check_value("PROJECTDOCSTRING_Id", 0x0005, uint32(projectdocstring_id))
	projectdocstring_sizeof_docstring := int(getUint32(dir_stream, &i))
	if projectdocstring_sizeof_docstring > 2000 {
		return nil, errors.New(fmt.Sprintf(
			"PROJECTDOCSTRING_SizeOfDocString value not in range: %v",
			projectdocstring_sizeof_docstring))
	}
	// projectdocstring_docstring := dir_stream[i : i+projectdocstring_sizeof_docstring]
	i += projectdocstring_sizeof_docstring

	projectdocstring_reserved := getUint16(dir_stream, &i)
	check_value("PROJECTDOCSTRING_Reserved", 0x0040, uint32(projectdocstring_reserved))
	projectdocstring_sizeof_docstring_unicode := int(getUint32(dir_stream, &i))

	if projectdocstring_sizeof_docstring_unicode%2 != 0 {
		return nil, errors.New("PROJECTDOCSTRING_SizeOfDocStringUnicode is not even")
	}
	//	projectdocstring_docstring_unicode := dir_stream[i : i+projectdocstring_sizeof_docstring_unicode]
	i += projectdocstring_sizeof_docstring_unicode

	// PROJECTHELPFILEPATH Record - MS-OVBA 2.3.4.2.1.7
	projecthelpfilepath_id := getUint16(dir_stream, &i)
	check_value("PROJECTHELPFILEPATH_Id", 0x0006, uint32(projecthelpfilepath_id))
	projecthelpfilepath_sizeof_helpfile1 := int(getUint32(dir_stream, &i))
	if projecthelpfilepath_sizeof_helpfile1 > 260 {
		return nil, errors.New(fmt.Sprintf(
			"PROJECTHELPFILEPATH_SizeOfHelpFile1 value not in range: %v", projecthelpfilepath_sizeof_helpfile1))
	}
	projecthelpfilepath_helpfile1 := dir_stream[i : i+projecthelpfilepath_sizeof_helpfile1]
	i += projecthelpfilepath_sizeof_helpfile1
	projecthelpfilepath_reserved := getUint16(dir_stream, &i)
	check_value("PROJECTHELPFILEPATH_Reserved", 0x003D, uint32(projecthelpfilepath_reserved))
	projecthelpfilepath_sizeof_helpfile2 := int(getUint32(dir_stream, &i))
	if projecthelpfilepath_sizeof_helpfile2 != projecthelpfilepath_sizeof_helpfile1 {
		return nil, errors.New("PROJECTHELPFILEPATH_SizeOfHelpFile1 does not equal PROJECTHELPFILEPATH_SizeOfHelpFile2")
	}
	projecthelpfilepath_helpfile2 := dir_stream[i : i+projecthelpfilepath_sizeof_helpfile2]
	i += projecthelpfilepath_sizeof_helpfile2
	if string(projecthelpfilepath_helpfile2) != string(projecthelpfilepath_helpfile1) {
		return nil, errors.New("PROJECTHELPFILEPATH_HelpFile1 does not equal PROJECTHELPFILEPATH_HelpFile2")
	}

	// PROJECTHELPCONTEXT Record
	projecthelpcontext_id := getUint16(dir_stream, &i)
	check_value("PROJECTHELPCONTEXT_Id", 0x0007, uint32(projecthelpcontext_id))
	projecthelpcontext_size := getUint32(dir_stream, &i)
	check_value("PROJECTHELPCONTEXT_Size", 0x0004, projecthelpcontext_size)

	// projecthelpcontext_helpcontext := getUint32(dir_stream, &i)
	i += 4

	// PROJECTLIBFLAGS Record
	projectlibflags_id := getUint16(dir_stream, &i)
	check_value("PROJECTLIBFLAGS_Id", 0x0008, uint32(projectlibflags_id))
	projectlibflags_size := getUint32(dir_stream, &i)
	check_value("PROJECTLIBFLAGS_Size", 0x0004, projectlibflags_size)
	projectlibflags_projectlibflags := getUint32(dir_stream, &i)
	check_value("PROJECTLIBFLAGS_ProjectLibFlags", 0x0000, projectlibflags_projectlibflags)

	// PROJECTVERSION Record
	projectversion_id := getUint16(dir_stream, &i)
	check_value("PROJECTVERSION_Id", 0x0009, uint32(projectversion_id))
	projectversion_reserved := getUint32(dir_stream, &i)
	check_value("PROJECTVERSION_Reserved", 0x0004, projectversion_reserved)

	/*
		projectversion_versionmajor := getUint32(dir_stream, &i)
		projectversion_versionminor := getUint16(dir_stream, &i)
	*/
	i += 6

	// PROJECTCONSTANTS Record
	projectconstants_id := getUint16(dir_stream, &i)
	if projectconstants_id == 0x000C {
		check_value("PROJECTCONSTANTS_Id", 0x000C, uint32(projectconstants_id))
		projectconstants_sizeof_constants := int(getUint32(dir_stream, &i))
		if projectconstants_sizeof_constants > 1015 {
			return nil, errors.New(fmt.Sprintf(
				"PROJECTCONSTANTS_SizeOfConstants value not in range: %v", projectconstants_sizeof_constants))
		}
		// projectconstants_constants := dir_stream[i : i+projectconstants_sizeof_constants]
		i += projectconstants_sizeof_constants
		projectconstants_reserved := getUint16(dir_stream, &i)
		check_value("PROJECTCONSTANTS_Reserved", 0x003C, uint32(projectconstants_reserved))
		projectconstants_sizeof_constants_unicode := int(getUint32(dir_stream, &i))
		if projectconstants_sizeof_constants_unicode%2 != 0 {
			return nil, errors.New("PROJECTCONSTANTS_SizeOfConstantsUnicode is not even")
		}
		// projectconstants_constants_unicode := dir_stream[i : i+projectconstants_sizeof_constants_unicode]
		i += projectconstants_sizeof_constants_unicode
	} else {
		i -= 2
	}

	// array of REFERENCE records
	var check uint16
loop:
	for {
		check = getUint16(dir_stream, &i)
		DebugPrintf("reference type = %04x", check)
		switch check {
		case 0x000F:
			break loop

		case 0x0016:
			// REFERENCENAME
			reference_sizeof_name := int(getUint32(dir_stream, &i))
			// reference_name := dir_stream[i : i+reference_sizeof_name]
			i += reference_sizeof_name
			reference_reserved := getUint16(dir_stream, &i)
			/*
			 # According to [MS-OVBA] 2.3.4.2.2.2 REFERENCENAME Record:
			 # "Reserved (2 bytes): MUST be 0x003E. MUST be ignored."
			 # So let's ignore it, otherwise it crashes on some files (issue #132)
			 # PR #135 by @c1fe:
			 # contrary to the specification I think that the unicode name
			 # is optional. if reference_reserved is not 0x003E I think it
			 # is actually the start of another REFERENCE record
			 # at least when projectsyskind_syskind == 0x02 (Macintosh)
			*/
			if reference_reserved == 0x003E {
				reference_sizeof_name_unicode := int(getUint32(dir_stream, &i))
				// reference_name_unicode := dir_stream[i : i+reference_sizeof_name_unicode]
				i += reference_sizeof_name_unicode
				continue loop
			} else {
				check = reference_reserved
				debug(fmt.Sprintf("reference type = %04x", check))
			}
		case 0x0033:
			// REFERENCEORIGINAL (followed by REFERENCECONTROL)
			referenceoriginal_sizeof_libidoriginal := int(getUint32(dir_stream, &i))

			// referenceoriginal_libidoriginal := dir_stream[i : i+referenceoriginal_sizeof_libidoriginal]
			i += referenceoriginal_sizeof_libidoriginal
			continue

		case 0x002F:
			// REFERENCECONTROL
			// referencecontrol_sizetwiddled := int(getUint32(dir_stream, &i))
			i += 4
			referencecontrol_sizeof_libidtwiddled := int(getUint32(dir_stream, &i))
			// referencecontrol_libidtwiddled := dir_stream[i : i+referencecontrol_sizeof_libidtwiddled]
			i += referencecontrol_sizeof_libidtwiddled
			referencecontrol_reserved1 := getUint32(dir_stream, &i)
			check_value("REFERENCECONTROL_Reserved1", 0x0000, referencecontrol_reserved1)
			referencecontrol_reserved2 := int(getUint16(dir_stream, &i))
			check_value("REFERENCECONTROL_Reserved2", 0x0000, uint32(referencecontrol_reserved2))

			// optional field
			check2 := int(getUint16(dir_stream, &i))
			var referencecontrol_reserved3 int

			if check2 == 0x0016 {
				referencecontrol_namerecordextended_sizeof_name := int(getUint32(dir_stream, &i))
				//referencecontrol_namerecordextended_name := dir_stream[i : i+ referencecontrol_namerecordextended_sizeof_name]
				i += referencecontrol_namerecordextended_sizeof_name
				referencecontrol_namerecordextended_reserved := int(getUint16(dir_stream, &i))
				if referencecontrol_namerecordextended_reserved == 0x003E {
					referencecontrol_namerecordextended_sizeof_name_unicode := int(getUint32(dir_stream, &i))
					// referencecontrol_namerecordextended_name_unicode := dir_stream[i : i+referencecontrol_namerecordextended_sizeof_name_unicode]
					i += referencecontrol_namerecordextended_sizeof_name_unicode
					referencecontrol_reserved3 = int(getUint16(dir_stream, &i))

				} else {
					referencecontrol_reserved3 = referencecontrol_namerecordextended_reserved
				}
			} else {
				referencecontrol_reserved3 = check2
			}
			check_value("REFERENCECONTROL_Reserved3", 0x0030, uint32(referencecontrol_reserved3))
			//referencecontrol_sizeextended := int(getUint32(dir_stream, &i))
			i += 4
			referencecontrol_sizeof_libidextended := int(getUint32(dir_stream, &i))
			// referencecontrol_libidextended := dir_stream[i : i+referencecontrol_sizeof_libidextended]
			i += referencecontrol_sizeof_libidextended
			// referencecontrol_reserved4 := int(getUint32(dir_stream, &i))
			// referencecontrol_reserved5 := int(getUint16(dir_stream, &i))
			// referencecontrol_originaltypelib := dir_stream[i : i+16]
			// referencecontrol_cookie := int(getUint32(dir_stream, &i))
			i += 6 + 16 + 4

			continue

		case 0x000D:
			// REFERENCEREGISTERED
			// referenceregistered_size := int(getUint32(dir_stream, &i))
			i += 4
			referenceregistered_sizeof_libid := int(getUint32(dir_stream, &i))
			// referenceregistered_libid := dir_stream[i : i+referenceregistered_sizeof_libid]
			i += referenceregistered_sizeof_libid
			referenceregistered_reserved1 := getUint32(dir_stream, &i)
			check_value("REFERENCEREGISTERED_Reserved1", 0x0000, referenceregistered_reserved1)
			referenceregistered_reserved2 := getUint16(dir_stream, &i)
			check_value("REFERENCEREGISTERED_Reserved2", 0x0000, uint32(referenceregistered_reserved2))

			continue

		case 0x000E:
			// REFERENCEPROJECT
			// referenceproject_size := getUint32(dir_stream, &i)
			i += 4
			referenceproject_sizeof_libidabsolute := int(getUint32(dir_stream, &i))
			// referenceproject_libidabsolute := dir_stream[i : i+referenceproject_sizeof_libidabsolute]
			i += referenceproject_sizeof_libidabsolute
			referenceproject_sizeof_libidrelative := int(getUint32(dir_stream, &i))
			// referenceproject_libidrelative := dir_stream[i : i+referenceproject_sizeof_libidrelative]
			i += referenceproject_sizeof_libidrelative
			// referenceproject_majorversion := getUint32(dir_stream, &i)
			// referenceproject_minorversion := getUint16(dir_stream, &i)
			i += 6
			continue
		default:
			return nil, fmt.Errorf("invalid or unknown check Id %04x", check)
		}
	}

	projectmodules_id := check
	check_value("PROJECTMODULES_Id", 0x000F, uint32(projectmodules_id))
	projectmodules_size := getUint32(dir_stream, &i)
	check_value("PROJECTMODULES_Size", 0x0002, projectmodules_size)
	projectmodules_count := getUint16(dir_stream, &i)
	projectmodules_projectcookierecord_id := getUint16(dir_stream, &i)

	check_value("PROJECTMODULES_ProjectCookieRecord_Id", 0x0013, uint32(projectmodules_projectcookierecord_id))
	projectmodules_projectcookierecord_size := getUint32(dir_stream, &i)

	check_value("PROJECTMODULES_ProjectCookieRecord_Size", 0x0002, uint32(projectmodules_projectcookierecord_size))

	// projectmodules_projectcookierecord_cookie := getUint16(dir_stream, &i)
	i += 2

	// short function to simplify unicode text output
	//    uni_out = lambda unicode_text: unicode_text.encode("utf-8", "replace")
	DebugPrintf("parsing %v modules", projectmodules_count)
	for projectmodule_index := 0; projectmodule_index < int(projectmodules_count); projectmodule_index++ {
		modulestreamname_streamname := ""
		modulestreamname_streamname_unicode := []byte{}
		moduleoffset_textoffset := uint32(0)

		modulename_id := getUint16(dir_stream, &i)

		check_value("MODULENAME_Id", 0x0019, uint32(modulename_id))
		modulename_sizeof_modulename := int(getUint32(dir_stream, &i))
		modulename_modulename := string(dir_stream[i : i+modulename_sizeof_modulename])
		i += modulename_sizeof_modulename

		// TODO: preset variables to avoid "referenced before assignment" errors
		modulename_unicode_modulename_unicode := []byte{}

		// account for optional sections
		section_id := getUint16(dir_stream, &i)
		if section_id == 0x0047 {
			modulename_unicode_sizeof_modulename_unicode := int(binary.LittleEndian.Uint32(dir_stream[i:]))
			i += 4
			modulename_unicode_modulename_unicode = dir_stream[i : i+
				modulename_unicode_sizeof_modulename_unicode]
			i += modulename_unicode_sizeof_modulename_unicode
			// just guessing that this is the same encoding as used in OleFileIO
			section_id = getUint16(dir_stream, &i)
		}

		if section_id == 0x001A {
			modulestreamname_sizeof_streamname := int(getUint32(dir_stream, &i))
			modulestreamname_streamname = string(dir_stream[i : i+modulestreamname_sizeof_streamname])
			i = i + modulestreamname_sizeof_streamname

			modulestreamname_reserved := getUint16(dir_stream, &i)
			check_value("MODULESTREAMNAME_Reserved", 0x0032, uint32(modulestreamname_reserved))
			modulestreamname_sizeof_streamname_unicode := int(getUint32(dir_stream, &i))
			modulestreamname_streamname_unicode = dir_stream[i : i+
				modulestreamname_sizeof_streamname_unicode]
			i += modulestreamname_sizeof_streamname_unicode

			// just guessing that this is the same encoding as used in OleFileIO
			section_id = getUint16(dir_stream, &i)
		}

		if section_id == 0x001C {
			moduledocstring_id := section_id
			check_value("MODULEDOCSTRING_Id", 0x001C, uint32(moduledocstring_id))
			moduledocstring_sizeof_docstring := int(getUint32(dir_stream, &i))

			// moduledocstring_docstring := dir_stream[i : i+moduledocstring_sizeof_docstring]
			i = i + moduledocstring_sizeof_docstring
			moduledocstring_reserved := getUint16(dir_stream, &i)
			check_value("MODULEDOCSTRING_Reserved", 0x0048, uint32(moduledocstring_reserved))
			moduledocstring_sizeof_docstring_unicode := int(getUint32(dir_stream, &i))
			// moduledocstring_docstring_unicode := dir_stream[i : i+moduledocstring_sizeof_docstring_unicode]
			i = i + moduledocstring_sizeof_docstring_unicode

			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x0031 {
			moduleoffset_id := section_id
			check_value("MODULEOFFSET_Id", 0x0031, uint32(moduleoffset_id))
			moduleoffset_size := getUint32(dir_stream, &i)

			check_value("MODULEOFFSET_Size", 0x0004, moduleoffset_size)
			moduleoffset_textoffset = getUint32(dir_stream, &i)
			section_id = getUint16(dir_stream, &i)
		}

		if section_id == 0x001E {
			modulehelpcontext_id := section_id
			check_value("MODULEHELPCONTEXT_Id", 0x001E, uint32(modulehelpcontext_id))
			modulehelpcontext_size := getUint32(dir_stream, &i)
			check_value("MODULEHELPCONTEXT_Size", 0x0004, modulehelpcontext_size)
			// modulehelpcontext_helpcontext := getUint32(dir_stream, &i)
			i += 4
			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x002C {
			modulecookie_id := section_id
			check_value("MODULECOOKIE_Id", 0x002C, uint32(modulecookie_id))
			modulecookie_size := getUint32(dir_stream, &i)
			check_value("MODULECOOKIE_Size", 0x0002, modulecookie_size)
			// modulecookie_cookie := getUint16(dir_stream, &i)
			i += 2
			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x0021 || section_id == 0x0022 {
			//moduletype_reserved := getUint32(dir_stream, &i)
			i += 4
			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x0025 {
			modulereadonly_id := section_id
			check_value("MODULEREADONLY_Id", 0x0025, uint32(modulereadonly_id))
			modulereadonly_reserved := getUint32(dir_stream, &i)
			check_value("MODULEREADONLY_Reserved", 0x0000, modulereadonly_reserved)
			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x0028 {
			moduleprivate_id := section_id
			check_value("MODULEPRIVATE_Id", 0x0028, uint32(moduleprivate_id))
			moduleprivate_reserved := getUint32(dir_stream, &i)
			check_value("MODULEPRIVATE_Reserved", 0x0000, moduleprivate_reserved)
			section_id = getUint16(dir_stream, &i)
		}
		if section_id == 0x002B { // TERMINATOR
			module_reserved := getUint32(dir_stream, &i)
			check_value("MODULE_Reserved", 0x0000, module_reserved)
			section_id = 0
		}
		if section_id != 0 {
			debug(fmt.Sprintf("unknown or invalid module section id %04x", section_id))
		}

		DebugPrintf("Project CodePage = %d", projectcodepage_codepage)
		DebugPrintf("ModuleName = %v", modulename_modulename)
		DebugPrintf(
			"ModuleNameUnicode = %v", decodeUnicode(
				modulename_unicode_modulename_unicode,
				projectcodepage_codepage))
		DebugPrintf("StreamName = %v", modulestreamname_streamname)
		DebugPrintf(
			"StreamNameUnicode = %v", decodeUnicode(
				modulestreamname_streamname_unicode,
				projectcodepage_codepage))
		DebugPrintf("TextOffset = %v", moduleoffset_textoffset)

		code_stream := ofdoc.FindStreamByName(modulestreamname_streamname)
		// This doc has no code stream
		if code_stream == nil {
			continue
		}
		code_data := ofdoc.GetStream(code_stream.Index)

		DebugPrintf("length of code_data = %v", len(code_data))
		DebugPrintf("offset of code_data = %v", moduleoffset_textoffset)
		code_data = code_data[moduleoffset_textoffset:]
		if len(code_data) > 0 {
			result = append(result, &VBAModule{
				Code: string(DecompressStream(code_data)),
				ModuleName: decodeUnicode(
					modulename_unicode_modulename_unicode,
					projectcodepage_codepage),
				StreamName: decodeUnicode(
					modulestreamname_streamname_unicode,
					projectcodepage_codepage),
				Type: code_modules[modulename_modulename],
			})
		}
	}

	return result, nil
}

func ParseFile(filename string) ([]*VBAModule, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	signature := make([]byte, len(OLE_SIGNATURE))
	_, err = io.ReadAtLeast(fd, signature, len(OLE_SIGNATURE))
	if err != nil {
		return nil, err
	}

	if string(signature) == OLE_SIGNATURE {
		fd.Seek(0, os.SEEK_SET)
		data, err := ioutil.ReadAll(fd)
		if err != nil {
			return nil, err
		}
		return ParseBuffer(data)
	}

	// Maybe the file is a zip file.
	r, err := zip.OpenReader(filename)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	results := []*VBAModule{}
	for _, f := range r.File {
		if BINFILE_NAME.MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, err
			}
			modules, err := ParseBuffer(data)
			if err == nil {
				results = append(results, modules...)
			}
		}
	}

	return results, nil
}

func ParseBuffer(data []byte) ([]*VBAModule, error) {

	olefile, err := NewOLEFile(data)
	if err != nil {
		return nil, err
	}

	macros, err := ExtractMacros(olefile)
	if err != nil {
		return nil, err
	}

	return macros, nil
}

func debug(message string) {
	// fmt.Println(message)
}

func decodeUnicode(data []byte, codepage uint16) string {
	// First decode from UTF16-LE
	unicode_data, err := unicode.UTF16(
		unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(data)
	if err != nil {
		return string(data)
	}

	// Now apply the relevant code page.
	decoder := charmap.Windows1252.NewDecoder()

	switch codepage {
	case 1252:
		decoder = charmap.Windows1252.NewDecoder()
	}

	res, err := decoder.Bytes(unicode_data)
	if err != nil {
		return string(unicode_data)
	}
	return string(res)
}
