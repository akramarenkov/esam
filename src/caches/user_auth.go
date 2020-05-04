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

package caches

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

import (
	"github.com/akramarenkov/esam/src/auth"
	"github.com/akramarenkov/esam/src/data"
	"github.com/akramarenkov/esam/src/types"
)

type UserAuth struct {
	filePath string
	user     data.UserAuth
	mutex    sync.RWMutex
}

func (cache *UserAuth) Init(filePath string) error {
	cache.filePath = filePath
	cache.user = data.UserAuth{}

	return nil
}

func (cache *UserAuth) FromFile() error {
	var (
		err       error
		cacheFile *os.File
		jsonDec   *json.Decoder
	)

	cacheFile, err = os.Open(cache.filePath)
	if err != nil {
		return err
	}
	defer cacheFile.Close()

	jsonDec = json.NewDecoder(cacheFile)

	cache.mutex.Lock()
	err = jsonDec.Decode(&cache.user)
	cache.mutex.Unlock()
	if err != nil {
		return err
	}

	return nil
}

func (cache *UserAuth) ToFile() error {
	var (
		err       error
		cacheFile *os.File
		jsonEnc   *json.Encoder
	)

	cacheFile, err = os.Open(cache.filePath)
	if err == nil {
		cacheFile.Close()
		os.Rename(cache.filePath, cache.filePath+".old")
	}

	cacheFile, err = os.OpenFile(cache.filePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer cacheFile.Close()

	jsonEnc = json.NewEncoder(cacheFile)

	err = nil
	cache.mutex.RLock()
	if !cache.user.Equal(&data.User{}) {
		err = jsonEnc.Encode(cache.user)
	}
	cache.mutex.RUnlock()
	if err != nil {
		return err
	}

	return nil
}

func (cache *UserAuth) Update(usersListDB []data.UserDB, userESAMPubKey *data.ESAMPubKey, verifyKey *data.ESAMPubKey) error {
	var (
		err error

		keyMatchesNumber int
		targetUserIndex  int
		trustedData      bool
	)

	for index := range usersListDB {
		if userESAMPubKey.Equal(&usersListDB[index].User.ESAMPubKey) {
			targetUserIndex = index
			keyMatchesNumber++
		}
	}

	if keyMatchesNumber == 0 {
		return errors.New("User not found")
	}

	if keyMatchesNumber > 1 {
		return errors.New("Multiplicity users found")
	}

	trustedData, err = auth.CheckUserDataAuthenticity(&usersListDB[targetUserIndex], usersListDB, verifyKey)
	cache.mutex.Lock()
	if err == nil && trustedData == true {
		cache.user.TrustedData = types.True
	} else {
		cache.user.TrustedData = types.False
	}
	cache.user.Name = usersListDB[targetUserIndex].User.Name
	cache.mutex.Unlock()

	return nil
}

func (cache *UserAuth) Get() data.UserAuth {
	var user data.UserAuth

	cache.mutex.RLock()
	user = cache.user
	cache.mutex.RUnlock()

	return user
}
