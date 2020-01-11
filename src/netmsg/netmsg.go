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

package netmsg

import (
  "errors"
  "net"
  "io"
  "strconv"
  "time"
)

import (
  "esam/src/opts"
)

const (
  sizeStringMaxSize = 16
  sizeStringSuppSymbol = "\000"
)

func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
  var err error
  var sizeString []byte
  var sizeStringSize int
  var msgSize uint64
  var msg []byte
  
  sizeString = make([]byte, sizeStringMaxSize)
  
  conn.SetReadDeadline(time.Now().Add(timeout))
  _, err = io.ReadFull(conn, sizeString)
  if err != nil {
    return nil, err
  }
  
  sizeStringSize = 0
  for index := 0; index < sizeStringMaxSize; index++ {
    switch string(sizeString[index]) {
      case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9": {
        sizeStringSize++
      }
      case sizeStringSuppSymbol:
      default: return nil, errors.New("Incorrect msg size format")
    }
  }
  
  msgSize, err = strconv.ParseUint(string(sizeString[:sizeStringSize]), 10, 64)
  if err != nil {
    return nil, err
  }
  
  if msgSize == 0 {
    return nil, errors.New("Msg size is zero")
  }
  
  if msgSize > opts.NetMaxMsgSize {
    return nil, errors.New("Msg size is too big")
  }
  
  msg = make([]byte, msgSize)
  
  conn.SetReadDeadline(time.Now().Add(timeout))
  _, err = io.ReadFull(conn, msg)
  if err != nil {
    return nil, err
  }
  
  return msg[:], nil
}

func Send(conn net.Conn, msg []byte, timeout time.Duration) (int, error) {
  var err error
  var writeLen int
  var msgSum []byte
  
  if len(msg) == 0 {
    return writeLen, errors.New("Msg size is zero")
  }
  
  msgSum = []byte(strconv.FormatUint(uint64(len(msg)), 10))
  
  if len(msgSum) > sizeStringMaxSize || uint64(len(msgSum)) > opts.NetMaxMsgSize {
    return writeLen, errors.New("Msg size is too big")
  }
  
  for len(msgSum) < sizeStringMaxSize {
    msgSum = append(msgSum, []byte(sizeStringSuppSymbol)...)
  }
  
  if len(msgSum) > sizeStringMaxSize {
    return writeLen, errors.New("Size string formatting error")
  }
  
  msgSum = append(msgSum, msg...)
  
  conn.SetWriteDeadline(time.Now().Add(timeout))
  writeLen, err = conn.Write(msgSum)
  if err != nil {
    return writeLen, err
  }
  
  return writeLen, nil
}

func IsTimeout(err error) bool {
  var netErr net.Error
  var castOk bool
  
  netErr, castOk = err.(net.Error)
  if castOk {
    if netErr.Timeout() {
      return true
    }
  }
  
  return false
}

func IsEOF(err error) bool {
  if err == io.EOF {
    return true
  }
  
  return false
}

func IsTemporary(err error) bool {
  var netErr net.Error
  var castOk bool
  
  netErr, castOk = err.(net.Error)
  if castOk {
    if netErr.Temporary() {
      return true
    }
  }
  
  return false
}
