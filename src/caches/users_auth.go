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
  "os"
  "encoding/json"
  "sync"
)

import (
  "esam/src/data"
  "esam/src/parallel"
)

type UsersAuth struct {
  filePath string
  list *[]data.UserAuth
  mutex sync.RWMutex
}

func (cache *UsersAuth) Init(filePath string) (error) {
  cache.filePath = filePath
  cache.list = &([]data.UserAuth{})
  
  return nil
}

func (cache *UsersAuth) FromFile() (error) {
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

func (cache *UsersAuth) ToFile() (error) {
  var err error
  var cacheFile *os.File
  var jsonEnc *json.Encoder
  
  cacheFile, err = os.Open(cache.filePath)
  if err == nil {
    cacheFile.Close()
    os.Rename(cache.filePath, cache.filePath + ".old")
  }
  
  cacheFile, err = os.OpenFile(cache.filePath, os.O_RDWR | os.O_CREATE, 0600)
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

func (cache *UsersAuth) Update(usersListDB []data.UserDB, verifyKey *data.ESAMPubKey, coresRatio float32) (error) {
  var err error
  var usersList []data.UserAuth
  
  usersList, err = parallel.MakeUserAuthList(usersListDB[:], verifyKey, coresRatio)
  if err != nil {
    return err
  }
  
  cache.mutex.Lock()
    cache.list = &usersList
  cache.mutex.Unlock()
  
  return nil
}

func (cache *UsersAuth) RLock() {
  cache.mutex.RLock()
}

func (cache *UsersAuth) RUnlock() {
  cache.mutex.RUnlock()
}

func (cache *UsersAuth) Get() ([]data.UserAuth) {
  return (*cache.list)[:]
}
