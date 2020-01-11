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

package setup

import (
  "errors"
  "os"
  "syscall"
  "strconv"
)

func FilePresent(path string, mode os.FileMode, uid, gid string) (*os.File, error) {
  var err error
  var file *os.File
  var fileInfo os.FileInfo
  var uidAsInt, gidAsInt uint64
  var fileStat *syscall.Stat_t
  var castOk bool
  
  if !mode.IsRegular() {
    return nil, errors.New("Mode describes not a regular file")
  }
  
  file, err = os.OpenFile(path, os.O_RDWR | os.O_CREATE , mode)
  if err != nil {
    return nil, err
  }
  
  fileInfo, err = file.Stat()
  if err != nil {
    return nil, err
  }
  
  if !fileInfo.Mode().IsRegular() {
    return nil, errors.New("Name of file already in use but is not a regular file")
  }
  
  uidAsInt, err = strconv.ParseUint(uid, 10, 32)
  if err != nil {
    return nil, err
  }
  
  gidAsInt, err = strconv.ParseUint(gid, 10, 32)
  if err != nil {
    return nil, err
  }
  
  fileStat, castOk = fileInfo.Sys().(*syscall.Stat_t)
  if fileStat == nil || !castOk {
    return nil, errors.New("Failed to stat file")
  }
  
  if fileInfo.Mode() != mode {
    err = os.Chmod(path, mode)
    if err != nil {
      return nil, err
    }
  }
  
  if fileStat.Uid != uint32(uidAsInt) || fileStat.Gid != uint32(gidAsInt) {
    err = os.Chown(path, int(uidAsInt), int(gidAsInt))
    if err != nil {
      return nil, err
    }
  }
  
  return file, nil
}

func FileAbsent(path string) (error) {
  var err error
  var fileInfo os.FileInfo
  
  fileInfo, err = os.Stat(path)
  if err != nil {
    return err
  }
  
  if !fileInfo.Mode().IsRegular() {
    return errors.New("Path does not point to a regular file")
  }
  
  err = os.Remove(path)
  if err != nil {
    return err
  }
  
  return nil
}
