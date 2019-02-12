package logger

import (
	"log"
	"os"

	"cloud.google.com/go/errorreporting"
)

// Log is a wrapper on the stdlib log pkg.
type Log struct {
	*log.Logger
	*errorreporting.Client
}

// New returns an initialized Log with defaults setup.
func New(prefix string, errorClient *errorreporting.Client) *Log {
	return &Log{
		log.New(os.Stdout, prefix, log.Lshortfile),
		errorClient,
	}
}
