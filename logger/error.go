package logger

import (
	"net/http"
	"path/filepath"
	"runtime"

	"cloud.google.com/go/errorreporting"
)

const (
	errObjectInvalid = "object is invalid"
	errObjectExists  = "object already exists"
)

// FatalIfErr checks if the error is nil and panics if not nil.
func (log *Log) FatalIfErr(err error) {
	if err == nil {
		return
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		log.Fatal(err)
	}
	log.Fatalf("%v\n %v:%v", err, filepath.Base(file), line)
}

// LogIfErr checks if the error is nil and logs it if not nil.
func (log *Log) LogIfErr(err error) error {
	if err == nil {
		return nil
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		log.Println(err)
	}
	log.Printf("%v\n %v:%v", err, filepath.Base(file), line)
	return err
}

func (log *Log) ErrReport(err error, user string, req *http.Request) {
	log.Report(errorreporting.Entry{
		Error: err,
		User:  user,
		Req:   req,
	})
	log.Print(err)
}
