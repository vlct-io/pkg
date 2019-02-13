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

package version

//go:generate go run make_version.go

import (
	"fmt"
	"time"
)

// These strings will be overwritten by an init function in
// created by make_version.go during the release process.
var (
	BuildTime = time.Time{}
	GitSHA    = ""
)

// Version returns a newline-terminated string describing the current
// version of the build.
func Version() string {
	if GitSHA == "" {
		return "devel\n"
	}
	str := fmt.Sprintf("Build time: %s\n", BuildTime.In(time.UTC).Format(time.Stamp+" 2006 UTC"))
	str += fmt.Sprintf("Git hash:   %s\n", GitSHA)
	return str
}
