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
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

// Hmac512 ciphers the data extracted from the Reader and returns
// a b64 encoded string of a SHA512 hash.
func Hmac512(key string, data io.Reader) (b64 string, err error) {
	hash := hmac.New(sha512.New, []byte(key))
	b, err := ioutil.ReadAll(data)
	if err != nil {
		return "", errors.Wrap(err, "unable to read data from reader")
	}
	if _, err := hash.Write(b); err != nil {
		return "", errors.Wrap(err, "unable to hash data")
	}
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}
