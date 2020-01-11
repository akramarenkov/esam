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
  "errors"
  "time"
  "strings"
  "reflect"
)

import (
  "github.com/jinzhu/copier"
  "gopkg.in/yaml.v3"
)

const (
  AccessReqSubjectUser = "user"
  AccessReqSubjectAgent = "agent"
)

type AccessReq struct {
  ESAMPubKey ESAMPubKey `yaml:"ESAM public key" json:"esam_pub_key" db:"esam_pub_key" sqltype:"VARBINARY(6144) NOT NULL PRIMARY KEY"`
  Subject string `yaml:"Subject" json:"subject" db:"subject" sqltype:"CHAR(16) NOT NULL"`
  Name string `yaml:"Name" json:"name" db:"name" sqltype:"CHAR(63)"`
}

type AccessReqInner struct {
  Addr string `yaml:"Addr" json:"addr" db:"addr" sqltype:"CHAR(45)"`
  Time time.Time `yaml:"Time" json:"time" db:"time" sqltype:"DATETIME"`
}

type AccessReqDB struct {
  AccessReq `yaml:",inline"`
  AccessReqInner `yaml:",inline"`
}

func (accessReq *AccessReq) TestSubject(toleratesEmptyFields bool) (error) {
  if accessReq == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if toleratesEmptyFields && len(accessReq.Subject) == 0 {
    return nil
  }
  
  switch accessReq.Subject {
    case AccessReqSubjectUser:
    case AccessReqSubjectAgent:
    
    default: return errors.New("Unsupported access request subject")
  }
  
  return nil
}

func (accessReq *AccessReq) Copy() (*AccessReq, error) {
  var err error
  var accessReqOut *AccessReq
  
  if accessReq == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  accessReqOut = new(AccessReq)
  
  err = copier.Copy(accessReqOut, accessReq)
  if err != nil {
    return nil, err
  }
  
  return accessReqOut, nil
}

func (accessReq *AccessReqDB) Copy() (*AccessReqDB, error) {
  var err error
  var accessReqOut *AccessReqDB
  
  if accessReq == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  accessReqOut = new(AccessReqDB)
  
  err = copier.Copy(accessReqOut, accessReq)
  if err != nil {
    return nil, err
  }
  
  return accessReqOut, nil
}

func (accessReq *AccessReq) Normalize(toleratesEmptyFields bool) (error) {
  var err error
  var accessReqTmp *AccessReq
  
  if accessReq == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  accessReqTmp, err = accessReq.Copy()
  if err != nil {
    return err
  }
  
  err = accessReqTmp.ESAMPubKey.Normalize(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  accessReqTmp.Subject = strings.TrimSpace(accessReqTmp.Subject)
  accessReqTmp.Name = strings.TrimSpace(accessReqTmp.Name)
  
  (*accessReq) = (*accessReqTmp)
  
  return nil
}

func (accessReq *AccessReq) Test(toleratesEmptyFields bool) (error) {
  var err error
  
  if accessReq == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = accessReq.ESAMPubKey.Test(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  err = accessReq.TestSubject(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  return nil
}

func (accessReq *AccessReq) Equal(accessReqTwo *AccessReq) (bool) {
  if accessReq == nil {
    return false
  }
  
  if accessReqTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(accessReq, accessReqTwo)
}

func (accessReq *AccessReqDB) Equal(accessReqTwo *AccessReqDB) (bool) {
  if accessReq == nil {
    return false
  }
  
  if accessReqTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(accessReq, accessReqTwo)
}

func (accessReq AccessReq) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(accessReq)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (accessReq *AccessReq) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), accessReq)
  if err != nil {
    return err
  }
  
  return nil
}

func (accessReq AccessReqDB) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(accessReq)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (accessReq *AccessReqDB) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), accessReq)
  if err != nil {
    return err
  }
  
  return nil
}
