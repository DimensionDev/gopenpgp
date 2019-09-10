// Package internal contains internal methods and constants.
package internal

import (
	"regexp"

	"github.com/DimensionDev/gopenpgp/constants"
)

// TrimNewlines removes whitespace from the end of each line of the input
// string.
func TrimNewlines(input string) string {
	var re = regexp.MustCompile(`(?m)[ \t]*$`)
	return re.ReplaceAllString(input, "")
}

// CreationTimeOffset stores the amount of seconds that a signature may be
// created in the future, to compensate for clock skew.
const CreationTimeOffset = int64(60 * 60 * 24 * 2)

// KeyArmorHeaders is a map of default armor headers for exported keys.
var KeyArmorHeaders = map[string]string{
	"Comment": constants.KeyArmorHeaderComment,
}

// MessageArmorHeaders is a map of default armor headers for exported messages.
var MessageArmorHeaders = map[string]string{
	"Comment": constants.MessageArmorHeaderComment,
}
