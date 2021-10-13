package oleparse

import "github.com/davecgh/go-spew/spew"

func Debug(arg interface{}) {
	spew.Dump(arg)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func uint32_min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
