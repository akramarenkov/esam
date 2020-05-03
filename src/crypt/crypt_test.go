/*
  ESAM - Elementary SSH accounts management
  Copyright (C) 2020 Aleksandr Kramarenko akramarenkov@yandex.ru

  This file is part of ESAM.

  ESAM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  ESAM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ESAM.  If not, see <https://www.gnu.org/licenses/>.
*/

package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
)

const (
	DefaultKeySize = 4096
)

func Test(t *testing.T) {
	var err error
	var key *rsa.PrivateKey
	var data []byte
	var signature []byte
	var encData []byte
	var decData []byte

	data = []byte("test message")
	fmt.Printf("Data = %+v\n", string(data[:]))

	key, err = rsa.GenerateKey(rand.Reader, DefaultKeySize)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to gen key", err)
		os.Exit(1)
	}

	signature, err = Sign(data[:], key)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign message", err)
		os.Exit(1)
	}

	fmt.Printf("Signature = %+v\n", signature[:])
	fmt.Printf("Signature len = %+v\n", len(signature[:]))

	err = Verify(data[:], &key.PublicKey, signature[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to verify sign message", err)
		os.Exit(1)
	}

	encData, err = Encrypt(data[:], &key.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to encrypt message", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted Data = %+v\n", encData[:])

	decData, err = Decrypt(encData[:], key)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to decrypt message", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypted Data = %+v\n", string(decData[:]))
}
