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

package svc

import (
	"strings"
	"unicode"
)

// length of string
// extract positions
// replace at positions

// Mask replaces every other char of a string with an *.
func Mask(data string) string {
	count := -1
	state := true
	transform := func(r rune) rune {
		if unicode.IsPunct(r) {
			return r
		}
		if count < 3 {
			count++
		} else {
			state = !state
			count = 0
		}
		if state {
			return '*'
		}
		return r
	}
	return strings.Map(transform, data)
}
