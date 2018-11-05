package crypto

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
	"unicode"
)

func NewPassword(len int) string {
	buff := make([]byte, len)
	rand.Seed(time.Now().UnixNano())
	rand.Read(buff)
	pwd := base64.StdEncoding.EncodeToString(buff)
	// pwd = strings.Replace(pwd, "=", "", -1)
	pwd = strings.TrimFunc(pwd, func(r rune) bool {
		if unicode.IsSymbol(r) || unicode.IsPunct(r) || unicode.IsControl(r) {
			return true
		}
		return false
	})
	return pwd[1:len]
}
