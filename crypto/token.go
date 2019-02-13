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
