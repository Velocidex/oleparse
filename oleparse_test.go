package oleparse

import (
	"encoding/json"
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
