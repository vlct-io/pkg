package crypto

import (
	"strings"

	"github.com/gobuffalo/uuid"
)

func NewToken(len int, isTest bool) string {
	// ensure the generator is seeded
	_, _ = RandomBytes(32)
	prefix := "tok_"
	if isTest {
		prefix += "test_"
	}
	uid := uuid.Must(uuid.NewV4()).String()
	uid = strings.Replace(uid, "-", "", -1)
	pwd := prefix + uid
	return pwd[:len]
}
