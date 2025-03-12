package oleparse

import (
	"archive/zip"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/sebdah/goldie"
)

func TestMacros(t *testing.T) {
	macros, err := ParseFile("test_data/xlswithmacro.xlsm")
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}

	serialized, _ := json.MarshalIndent(macros, " ", " ")
	goldie.Assert(t, "vba_macros", serialized)
}

func FuzzExtractMacros(f *testing.F) {
	r, err := zip.OpenReader("test_data/xlswithmacro.xlsm")
	if err != nil {
		f.Fatal(err)
	}
	defer r.Close()

	for _, file := range r.File {
		if BINFILE_NAME.MatchString(file.Name) {
			rc, err := file.Open()
			if err != nil {
				f.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(data)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		modules, err := ParseBuffer(data)
		if err != nil {
			t.Skip()
		}
		var macros strings.Builder
		for _, module := range modules {
			macros.WriteString(module.Code)
		}
		t.Log(macros.String())
	})
}

func FuzzDecompressStream(f *testing.F) {
	r, err := zip.OpenReader("test_data/xlswithmacro.xlsm")
	if err != nil {
		f.Fatal(err)
	}
	defer r.Close()

	for _, file := range r.File {
		if BINFILE_NAME.MatchString(file.Name) {
			rc, err := file.Open()
			if err != nil {
				f.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				f.Fatal(err)
			}

			oleFile, err := NewOLEFile(data)
			if err != nil {
				f.Fatal(err)
			}

			for _, dir := range oleFile.Directory {
				f.Add(dir.data)
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decompressed := DecompressStream(data)
		t.Log(decompressed)
	})
}
