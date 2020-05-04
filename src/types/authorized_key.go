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

package types

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

import (
	"github.com/jinzhu/copier"
	"golang.org/x/crypto/ssh"
)

const (
	optionsDelimeter  = ","
	sectionsDelimeter = " "
)

type AuthorizedKey struct {
	Key     string
	Options []string
	Comment string
}

func (key *AuthorizedKey) Copy() (*AuthorizedKey, error) {
	var (
		err    error
		keyOut *AuthorizedKey
	)

	if key == nil {
		return nil, errors.New("Source struct pointer can't be nil")
	}

	keyOut = new(AuthorizedKey)

	err = copier.Copy(keyOut, key)
	if err != nil {
		return nil, err
	}

	return keyOut, nil
}

func (key *AuthorizedKey) FromBlock(block []byte) ([]byte, error) {
	var (
		err         error
		sshKey      ssh.PublicKey
		keyTmp      AuthorizedKey
		restOfBlock []byte
	)

	sshKey, keyTmp.Comment, keyTmp.Options, restOfBlock, err = ssh.ParseAuthorizedKey(block)
	if err != nil {
		return nil, err
	}

	keyTmp.Key = string(ssh.MarshalAuthorizedKey(sshKey))
	keyTmp.Key = strings.TrimRight(keyTmp.Key, "\n")

	(*key) = keyTmp

	return restOfBlock, nil
}

func (key *AuthorizedKey) FromString(stringIn string) error {
	var (
		err error
	)

	_, err = key.FromBlock([]byte(stringIn))
	if err != nil {
		return err
	}

	return nil
}

func (key *AuthorizedKey) String() string {
	var (
		out string
	)

	for index := range key.Options {
		if key.Options[index] != "" {
			if out == "" {
				out = key.Options[index]
			} else {
				out = out + optionsDelimeter + key.Options[index]
			}
		}
	}

	if key.Key != "" {
		if out == "" {
			out = key.Key
		} else {
			out = out + sectionsDelimeter + key.Key
		}
	}

	if key.Comment != "" {
		if out == "" {
			out = key.Comment
		} else {
			out = out + sectionsDelimeter + key.Comment
		}
	}

	return out
}

func (key *AuthorizedKey) Normalize() error {
	var (
		err error
	)

	err = key.FromString(key.String())
	if err != nil {
		return err
	}

	return nil
}

func (key *AuthorizedKey) Test() error {
	var (
		err    error
		keyTmp AuthorizedKey
	)

	err = keyTmp.FromString(key.String())
	if err != nil {
		return err
	}

	return nil
}

func NormalizeSSHPublicKey(keyAsString string) (string, error) {
	var (
		err error
		key AuthorizedKey
	)

	err = key.FromString(keyAsString)
	if err != nil {
		return keyAsString, err
	}

	return key.String(), nil
}

func TestSSHPublicKey(keyAsString string) error {
	var (
		err error
		key AuthorizedKey
	)

	err = key.FromString(keyAsString)
	if err != nil {
		return err
	}

	return nil
}

func AuthorizedKeysFromFile(file *os.File) ([]AuthorizedKey, error) {
	var (
		err         error
		keys        []AuthorizedKey
		fileContent []byte
		keysBlock   []byte
	)

	keys = make([]AuthorizedKey, 0)

	fileContent, err = ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	keysBlock = fileContent
	for len(keysBlock) > 0 {
		var (
			key         AuthorizedKey
			restOfBlock []byte
		)

		restOfBlock, err = key.FromBlock(keysBlock)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)

		keysBlock = restOfBlock
	}

	return keys, nil
}

func AuthorizedKeysToFile(file *os.File, keys []AuthorizedKey) error {
	var (
		err error
	)

	for index := range keys {
		_, err = file.Write([]byte(keys[index].String() + "\n"))
		if err != nil {
			return err
		}
	}

	return nil
}
