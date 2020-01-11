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
  "strings"
  "sort"
  "crypto/rsa"
  "reflect"
)

import (
  "github.com/jinzhu/copier"
  "gopkg.in/yaml.v3"
)

import (
  "esam/src/types"
  "esam/src/users"
)

const (
  UserRoleOwner = "owner"
  UserRoleSecAdmin = "sec_admin"
  UserRoleEngineer = "engineer"
)

const (
  UserStateEnabled = "enabled"
  UserStateSuspended = "suspended"
  UserStateDisabled = "disabled"
)

var (
  userRoles = map[string]string {
    UserRoleOwner: UserRoleOwner,
    UserRoleSecAdmin: UserRoleSecAdmin,
    UserRoleEngineer: UserRoleEngineer,
  }
  
  userStates = map[string]string {
    UserStateEnabled: UserStateEnabled,
    UserStateSuspended: UserStateSuspended,
    UserStateDisabled: UserStateDisabled,
  }
)

type User struct {
  ESAMPubKey ESAMPubKey `yaml:"ESAM public key" json:"esam_pub_key" db:"esam_pub_key" sqltype:"VARBINARY(6144) NOT NULL PRIMARY KEY"`
  Name string `yaml:"Name" json:"name" db:"name" sqltype:"CHAR(63) NOT NULL UNIQUE"`
  Role string `yaml:"Role" json:"role" db:"role" sqltype:"CHAR(32) NOT NULL"`
  State string `yaml:"State" json:"state" db:"state" sqltype:"CHAR(32) NOT NULL"`
  SSHPubKey string `yaml:"SSH public key" json:"ssh_pub_key" db:"ssh_pub_key" sqltype:"TEXT"`
  PasswordHash string `yaml:"Password hash" json:"password_hash" db:"password_hash" sqltype:"TEXT"`
  ElevatePrivileges bool `yaml:"Can elevate privileges" json:"elevate_privileges" db:"elevate_privileges" sqltype:"BOOLEAN"`
}

type UserSign struct {
  ESAMPubKeySign []byte `json:"esam_pub_key_sign" db:"esam_pub_key_sign" sqltype:"VARBINARY(4096)"`
  NameSign []byte `json:"name_sign" db:"name_sign" sqltype:"VARBINARY(4096)"`
  RoleSign []byte `json:"role_sign" db:"role_sign" sqltype:"VARBINARY(4096)"`
  StateSign []byte `json:"state_sign" db:"state_sign" sqltype:"VARBINARY(4096)"`
  SSHPubKeySign []byte `json:"ssh_pub_key_sign" db:"ssh_pub_key_sign" sqltype:"VARBINARY(4096)"`
  PasswordHashSign []byte `json:"password_hash_sign" db:"password_hash_sign" sqltype:"VARBINARY(4096)"`
  ElevatePrivilegesSign []byte `json:"elevate_privileges_sign" db:"elevate_privileges_sign" sqltype:"VARBINARY(4096)"`
  SignSubject ESAMPubKey `json:"sign_subject" db:"sign_subject" sqltype:"VARBINARY(6144) NOT NULL"`
}

type UserDB struct {
  User
  UserSign
}

/* Validated to data authenticity */
type UserAuth struct {
  User `yaml:",inline"`
  TrustedData string `yaml:"Trusted data" json:"trusted_data"`
}

func (user *User) TestRole(toleratesEmptyFields bool) (error) {
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if toleratesEmptyFields && len(user.Role) == 0 {
    return nil
  }
  
  if userRoles[user.Role] == "" {
    return errors.New("Unsupported user role")
  }
  
  return nil
}

func (user *User) TestState(toleratesEmptyFields bool) (error) {
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if toleratesEmptyFields && len(user.State) == 0 {
    return nil
  }
  
  if userStates[user.State] == "" {
    return errors.New("Unsupported user state")
  }
  
  return nil
}

func TemplateRoles() (string) {
  var roles []string
  
  roles = make([]string, 0)
  
  for _, role := range userRoles {
    roles = append(roles, role)
  }
  
  sort.Strings(roles)
  
  return strings.Join(roles, " | ")
}

func TemplateStates() (string) {
  var states []string
  
  states = make([]string, 0)
  
  for _, state := range userStates {
    states = append(states, state)
  }
  
  sort.Strings(states)
  
  return strings.Join(states, " | ")
}

func (user *User) Copy() (*User, error) {
  var err error
  var userOut *User
  
  if user == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  userOut = new(User)
  
  err = copier.Copy(userOut, user)
  if err != nil {
    return nil, err
  }
  
  return userOut, nil
}

func (user *UserDB) Copy() (*UserDB, error) {
  var err error
  var userOut *UserDB
  
  if user == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  userOut = new(UserDB)
  
  err = copier.Copy(userOut, user)
  if err != nil {
    return nil, err
  }
  
  return userOut, nil
}

func (user *UserAuth) Copy() (*UserAuth, error) {
  var err error
  var userOut *UserAuth
  
  if user == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  userOut = new(UserAuth)
  
  err = copier.Copy(userOut, user)
  if err != nil {
    return nil, err
  }
  
  return userOut, nil
}

func (user *User) Normalize(toleratesEmptyFields bool) (error) {
  var err error
  var userTmp *User
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return err
  }
  
  err = userTmp.ESAMPubKey.Normalize(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  if userTmp.SSHPubKey != "" {
    userTmp.SSHPubKey, err = types.NormalizeSSHPublicKey(userTmp.SSHPubKey)
    if err != nil {
      return err
    }
  }
  
  userTmp.Name = strings.TrimSpace(userTmp.Name)
  userTmp.Role = strings.TrimSpace(userTmp.Role)
  userTmp.State = strings.TrimSpace(userTmp.State)
  userTmp.PasswordHash = strings.TrimSpace(userTmp.PasswordHash)
  
  (*user) = (*userTmp)
  
  return nil
}

func (user *UserDB) Normalize() (error) {
  var err error
  var userTmp *UserDB
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return err
  }
  
  userTmp.User.Normalize(ToleratesEmptyFieldsNo)
  if err != nil {
    return err
  }
  
  if userTmp.UserSign.SignSubject.Len() < 1 {
    userTmp.UserSign.SignSubject.Template()
    if err != nil {
      return err
    }
  }
  
  (*user) = (*userTmp)
  
  return nil
}

func (user *UserAuth) Normalize(toleratesEmptyFields bool) (error) {
  var err error
  var userTmp *UserAuth
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return err
  }
  
  userTmp.User.Normalize(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  userTmp.TrustedData = types.NormalizeBoolString(userTmp.TrustedData)
  
  (*user) = (*userTmp)
  
  return nil
}

func (user *User) Test(toleratesEmptyFields bool) (error) {
  var err error
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = user.ESAMPubKey.Test(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  if toleratesEmptyFields && user.Name == "" {
  } else {
    err = users.ValidateName(user.Name)
    if err != nil {
      return err
    }
  }
  
  err = user.TestRole(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  err = user.TestState(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  if user.SSHPubKey != "" {
    err = types.TestSSHPublicKey(user.SSHPubKey)
    if err != nil {
      return err
    }
  }
  
  return nil
}

func (user *UserDB) Test() (error) {
  var err error
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = user.User.Test(ToleratesEmptyFieldsNo)
  if err != nil {
    return err
  }
  
  if user.UserSign.SignSubject.Len() < 1 {
    return errors.New("Sign subject can't be empty")
  }
  
  return nil
}

func (user *UserAuth) Test(toleratesEmptyFields bool) (error) {
  var err error
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = user.User.Test(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  err = types.TestBoolString(user.TrustedData, toleratesEmptyFields)
  
  return nil
}

func (user *User) Equal(userTwo *User) (bool) {
  if user == nil {
    return false
  }
  
  if userTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(user, userTwo)
}

func (user *UserDB) Equal(userTwo *UserDB) (bool) {
  if user == nil {
    return false
  }
  
  if userTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(user, userTwo)
}

func (user *UserDB) Sign(key *rsa.PrivateKey, selfSignedFields map[string]bool) (error) {
  var err error
  var userTmp *UserDB
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if key == nil {
    return errors.New("Key pointer can't be nil")
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return err
  }
  
  err = signStruct(&userTmp.User, &userTmp.UserSign, key, selfSignedFields)
  if err != nil {
    return err
  }
  
  (*user) = (*userTmp)
  
  return nil
}

func (user *UserDB) Verify(selfSignedFields map[string]bool) (error) {
  var err error
  
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = verifyStruct(&user.User, &user.UserSign, selfSignedFields)
  if err != nil {
    return err
  }
  
  return nil
}

/* Ugly but worked and simple implementation */
func (user *User) EqualWithIgnoreFields(userTwo *User, ignoreFields map[string]bool) (bool) {
  var err error
  var userTmp *User
  var userTwoTmp *User
  
  if user == nil {
    return false
  }
  
  if userTwo == nil {
    return false
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return false
  }
  
  userTwoTmp, err = userTwo.Copy()
  if err != nil {
    return false
  }
  
  err = zeroTwoStructsFields(userTmp, userTwoTmp, ignoreFields)
  if err != nil {
    return false
  }
  
  return userTmp.Equal(userTwoTmp)
}

func (user *UserDB) EqualWithIgnoreFields(userTwo *UserDB, ignoreFields map[string]bool) (bool) {
  var err error
  var userTmp *UserDB
  var userTwoTmp *UserDB
  
  if user == nil {
    return false
  }
  
  if userTwo == nil {
    return false
  }
  
  userTmp, err = user.Copy()
  if err != nil {
    return false
  }
  
  userTwoTmp, err = userTwo.Copy()
  if err != nil {
    return false
  }
  
  err = zeroTwoStructsFields(userTmp, userTwoTmp, ignoreFields)
  if err != nil {
    return false
  }
  
  return userTmp.Equal(userTwoTmp)
}

func (user User) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(user)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (user *User) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), user)
  if err != nil {
    return err
  }
  
  return nil
}

func (user UserAuth) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(user)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (user *UserAuth) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), user)
  if err != nil {
    return err
  }
  
  return nil
}

func (user *User) Template() (error) {
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  user.ESAMPubKey.Template()
  user.Role = TemplateRoles()
  user.State = TemplateStates()
  
  return nil
}

func (user *UserDB) Template() (error) {
  if user == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  user.User.Template()
  user.UserSign.SignSubject.Template()
  
  return nil
}
