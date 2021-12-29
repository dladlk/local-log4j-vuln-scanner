package main

import (
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Expected %v but found %v", expected, actual)
		debug.PrintStack()
		t.FailNow()
	}
}

func TestFormat(t *testing.T) {
	const thousand = 1000
	const million = 1000000
	assertEquals(t, "1.000", wrapThousand("1000"))
	assertEquals(t, "100.100", wrapThousand("100100"))
	assertEquals(t, "1.001.000", wrapThousand("1001000"))
	assertEquals(t, "101.001.000", wrapThousand("101001000"))
	assertEquals(t, "1001.001.000", wrapThousand("1001001000"))

	assertEquals(t, "10K", formatCount(10*thousand+1))
	assertEquals(t, "3M", formatCount(3*million))
	assertEquals(t, "3.1M", formatCount(3*million+50*thousand+1))
	assertEquals(t, "10K", formatCount(100*100))
	assertEquals(t, "1.001", formatCount(thousand+1))
	assertEquals(t, "1", formatCount(1))

	println("Done")
}
