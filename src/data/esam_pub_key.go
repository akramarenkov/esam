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

package data

import (
	"bytes"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
)

import (
	"github.com/akramarenkov/esam/src/keysconv"
)

import (
	"gopkg.in/yaml.v3"
)

/* RSA public key in PEM format */

type ESAMPubKey []byte

func (key *ESAMPubKey) Copy() (*ESAMPubKey, error) {
	var (
		keyOut ESAMPubKey
	)

	if key == nil {
		return nil, errors.New("Source key pointer can't be nil")
	}

	keyOut = make(ESAMPubKey, len((*key)))
	copy(keyOut, (*key))

	return &keyOut, nil
}

func (key *ESAMPubKey) Normalize(toleratesEmptyFields bool) error {
	var (
		err           error
		keyInRSA      *rsa.PublicKey
		keyNormalized ESAMPubKey
	)

	if key == nil {
		return errors.New("Key pointer can't be nil")
	}

	if toleratesEmptyFields && len((*key)) == 0 {
		return nil
	}

	keyInRSA, err = keysconv.PubKeyInPEMToRSA((*key))
	if err != nil {
		return errors.New("Key format is incorrect")
	}

	keyNormalized, err = keysconv.PubKeyInRSAToPEM(keyInRSA)
	if err != nil {
		return err
	}

	(*key) = keyNormalized

	return nil
}

func (key *ESAMPubKey) Test(toleratesEmptyFields bool) error {
	var (
		err error
	)

	if key == nil {
		return errors.New("Key pointer can't be nil")
	}

	if toleratesEmptyFields && len((*key)) == 0 {
		return nil
	}

	_, err = keysconv.PubKeyInPEMToRSA((*key))
	if err != nil {
		return errors.New("Key format is incorrect")
	}

	return nil
}

func (key *ESAMPubKey) Equal(keyTwo *ESAMPubKey) bool {
	if key == nil {
		return false
	}

	if keyTwo == nil {
		return false
	}

	return bytes.Equal((*key), (*keyTwo))
}

func (key *ESAMPubKey) EqualConstantTime(keyTwo *ESAMPubKey) bool {
	if key == nil {
		return false
	}

	if keyTwo == nil {
		return false
	}

	if subtle.ConstantTimeCompare((*key), (*keyTwo)) == 1 {
		return true
	} else {
		return false
	}

	return false
}

func (key *ESAMPubKey) Len() int {
	if key == nil {
		return -1
	}

	return len((*key))
}

func (key ESAMPubKey) MarshalYAML() (interface{}, error) {
	return string(key), nil
}

func (key *ESAMPubKey) UnmarshalYAML(value *yaml.Node) error {
	(*key) = []byte(value.Value)

	return nil
}

func (key *ESAMPubKey) Template() error {
	(*key) = []byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")

	return nil
}
