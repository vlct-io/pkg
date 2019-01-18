package crypto

import (
	"log"
	"math/rand"
	"strings"
	"time"
		"github.com/gobuffalo/uuid"

)

func NewToken(len int, isTest bool) string {
	prefix := "tok_"
	if isTest {
		prefix += "test_"
	}
	buff := make([]byte, len)
	rand.Seed(time.Now().UnixNano())
	rand.Read(buff)
	id := uuid.Must(uuid.NewV4()).String()
	log.Println(id)
	id = strings.Replace(id, "-", "", -1)
	pwd:=prefix + id
	return pwd[0:len]
}
