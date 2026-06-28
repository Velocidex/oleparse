package oleparse

import "github.com/davecgh/go-spew/spew"

func Debug(arg interface{}) {
	spew.Dump(arg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hasBytes(data []byte, offset, size int) bool {
	return offset >= 0 && size >= 0 && offset <= len(data) && size <= len(data)-offset
}

func skipBytes(data []byte, offset *int, size int) bool {
	if offset == nil || !hasBytes(data, *offset, size) {
		return false
	}
	*offset += size
	return true
}
