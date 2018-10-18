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
