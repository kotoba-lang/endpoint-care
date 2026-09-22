package disk

import "strconv"

// round1 rounds to one decimal place.
func round1(v float64) float64 {
	// math.Round to 1/10 without importing math twice in disk.go.
	if v < 0 {
		return -round1(-v)
	}
	i := int64(v*10 + 0.5)
	return float64(i) / 10
}

// trimRune formats with one decimal and drops a trailing ".0".
func trimRune(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	if len(s) > 2 && s[len(s)-2:] == ".0" {
		return s[:len(s)-2]
	}
	return s
}
