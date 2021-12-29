package main

import (
	"fmt"
	"math"
)

func formatDouble(d float64) string {
	if _, f := math.Modf(d); f < 0.01 {
		return fmt.Sprintf("%.0f", d)
	}
	return fmt.Sprintf("%.1f", d)
}

const SuffixThousand = "K"
const SuffixMillion = "M"

func formatCount(count int) string {
	if count > 2000 {
		var k = float64(count) / 1000.0
		if k > 2000 {
			var m = k / 1000.0
			return formatDouble(m) + SuffixMillion
		} else {
			return formatDouble(k) + SuffixThousand
		}
	}
	return wrapThousand(fmt.Sprintf("%d", count))
}

func wrapThousand(s string) string {
	var l = len(s)
	if l > 3 {
		// Go fmt does not have a feature to add dots between a thousand groups...
		// For fast solution to cover most real cases - support at least 100.000.000
		s = s[:l-3] + "." + s[l-3:]
		if l > 6 {
			s = s[:l-6] + "." + s[l-6:]
		}
	}
	return s
}

func formatDuration(ms int64) string {
	return formatCount(int(ms)) + " ms"
}
