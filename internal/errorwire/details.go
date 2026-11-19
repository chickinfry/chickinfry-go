// Package errorwire validates optional public operation error details.
package errorwire

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxFields = 32

var (
	codePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)
	pathPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*|\[(?:0|[1-9][0-9]{0,9})\])*$`)
)

func ValidCode(code string) bool {
	return codePattern.MatchString(code)
}

func ValidMessage(message string) bool {
	return len(message) <= 1024 && utf8.ValidString(message) && !strings.ContainsFunc(message, func(r rune) bool {
		return r <= 0x1f || r >= 0x7f && r <= 0x9f || r == '\u2028' || r == '\u2029'
	})
}

func ValidField(path, code string) bool {
	if len(path) > 256 || !pathPattern.MatchString(path) || !ValidCode(code) {
		return false
	}
	for _, tail, found := strings.Cut(path, "["); found; _, tail, found = strings.Cut(tail, "[") {
		index, _, _ := strings.Cut(tail, "]")
		if _, err := strconv.ParseUint(index, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// encoding/json replaces unpaired surrogate escapes; reject them before dispatch.
func ValidUnicodeJSON(data []byte) bool {
	inside := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
