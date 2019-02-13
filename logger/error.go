// Copyright 2019 Vaultex, Inc
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License a
//
//    http://www.apache.org/licenses/LICENSE-2.
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

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
