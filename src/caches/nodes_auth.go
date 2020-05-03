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
	"os"
	"sync"
)

import (
	"github.com/akramarenkov/esam/src/data"
	"github.com/akramarenkov/esam/src/parallel"
)

type NodesAuth struct {
	filePath string
	list     *[]data.NodeAuth
	mutex    sync.RWMutex
}

func (cache *NodesAuth) Init(filePath string) error {
	cache.filePath = filePath
	cache.list = &([]data.NodeAuth{})

	return nil
}

func (cache *NodesAuth) FromFile() error {
	var err error
	var cacheFile *os.File
	var jsonDec *json.Decoder

	cacheFile, err = os.Open(cache.filePath)
	if err != nil {
		return err
	}
	defer cacheFile.Close()

	jsonDec = json.NewDecoder(cacheFile)

	cache.mutex.Lock()
	err = jsonDec.Decode(cache.list)
	cache.mutex.Unlock()
	if err != nil {
		return err
	}

	return nil
}

func (cache *NodesAuth) ToFile() error {
	var err error
	var cacheFile *os.File
	var jsonEnc *json.Encoder

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
	if len((*cache.list)[:]) > 0 {
		err = jsonEnc.Encode((*cache.list)[:])
	}
	cache.mutex.RUnlock()
	if err != nil {
		return err
	}

	return nil
}

func (cache *NodesAuth) Update(nodesListDB []data.NodeDB, usersListDB []data.UserDB, verifyKey *data.ESAMPubKey, coresRatio float32) error {
	var err error
	var nodesList []data.NodeAuth

	nodesList, err = parallel.MakeNodeAuthList(nodesListDB[:], usersListDB[:], verifyKey, coresRatio)
	if err != nil {
		return err
	}

	cache.mutex.Lock()
	cache.list = &nodesList
	cache.mutex.Unlock()

	return nil
}

func (cache *NodesAuth) RLock() {
	cache.mutex.RLock()
}

func (cache *NodesAuth) RUnlock() {
	cache.mutex.RUnlock()
}

func (cache *NodesAuth) Get() []data.NodeAuth {
	return (*cache.list)[:]
}
