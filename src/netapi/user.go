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

package netapi

import (
	"encoding/json"
	"errors"
)

import (
	"github.com/akramarenkov/esam/src/data"
)

/*
{ "msg": { "type": "request", "request": "add_user" }, "user": { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "", "esam_pub_key_sign": "", "name_sign": "", "role_sign": "", "ssh_pub_key_sign": "", "password_hash_sign": "", "sign_subject": "" } }
{ "msg": { "type": "reply", "request": "add_user" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "add_user" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "add_user" }, "result": { "status": "failed", "reason": "Invalid signature" } }
{ "msg": { "type": "reply", "request": "add_user" }, "result": { "status": "failed", "reason": "Already exist" } }
{ "msg": { "type": "reply", "request": "add_user" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "update_user" }, "esam_pub_key": "", "user": { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "", "esam_pub_key_sign": "", "name_sign": "", "role_sign": "", "ssh_pub_key_sign": "", "password_hash_sign": "", "sign_subject": "" } }
{ "msg": { "type": "reply", "request": "update_user" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "update_user" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "update_user" }, "result": { "status": "failed", "reason": "Invalid signature" } }
{ "msg": { "type": "reply", "request": "update_user" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "update_user" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "change_password" }, "password": "", "password_hash": "", "password_hash_sign": "" }
{ "msg": { "type": "reply", "request": "change_password" }, "result": { "status": "failed", "reason": "Password too simple" } }
{ "msg": { "type": "reply", "request": "change_password" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "list_users" }, "filter": { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "" } }
{ "msg": { "type": "reply", "request": "list_users" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "list_users" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "list_users" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "list_users" }, "result": { "status": "successful", "reason": "" }, "users": [ { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "", "esam_pub_key_sign": "", "name_sign": "", "role_sign": "", "ssh_pub_key_sign": "", "password_hash_sign": "", "sign_subject": "" }, { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "", "esam_pub_key_sign": "", "name_sign": "", "role_sign": "", "ssh_pub_key_sign": "", "password_hash_sign": "", "sign_subject": "" } ] }
*/

/*
{ "msg": { "type": "request", "request": "get_auth_user_data" } }
{ "msg": { "type": "reply", "request": "get_auth_user_data" }, "result": { "status": "failed", "reason": "" } }
{ "msg": { "type": "reply", "request": "get_auth_user_data" }, "result": { "status": "successful", "reason": "" }, "auth_user_data": { "esam_pub_key": "", "name": "", "role": "", "state": "", "ssh_pub_key": "", "password_hash": "", "elevate_privileges": "", "trusted_data": "" } }
*/

/*
{ "msg": { "type": "request", "request": "del_user" }, "esam_pub_key": "" }
{ "msg": { "type": "reply", "request": "del_user" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "del_user" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "del_user" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "del_user" }, "result": { "status": "successful", "reason": "" } }
*/

/*Add */

type reqAddUser struct {
	msgHeaderWrapper
	data.UserDB `json:"user"`
}

func BuildReqAddUser(userIn *data.UserDB) ([]byte, error) {
	var err error
	var req []byte
	var reqAddUser reqAddUser

	reqAddUser.MsgHeader.Type = MsgTypeRequest
	reqAddUser.MsgHeader.SubType = ReqTypeAddUser
	reqAddUser.UserDB = (*userIn)

	req, err = json.Marshal(reqAddUser)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqAddUser(jsonIn []byte, userOut *data.UserDB) error {
	var err error
	var reqAddUser reqAddUser

	err = json.Unmarshal(jsonIn[:], &reqAddUser)
	if err != nil {
		return err
	}

	if reqAddUser.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqAddUser.MsgHeader.SubType != ReqTypeAddUser {
		return errors.New("Unexpected request type")
	}

	(*userOut) = reqAddUser.UserDB

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Add */

/* Update */

type reqUpdateUser struct {
	msgHeaderWrapper
	data.ESAMPubKey `json:"esam_pub_key"`
	data.UserDB     `json:"user"`
}

func BuildReqUpdateUser(esamPubKeyIn *data.ESAMPubKey, userIn *data.UserDB) ([]byte, error) {
	var err error
	var req []byte
	var reqUpdateUser reqUpdateUser

	reqUpdateUser.MsgHeader.Type = MsgTypeRequest
	reqUpdateUser.MsgHeader.SubType = ReqTypeUpdateUser
	reqUpdateUser.ESAMPubKey = (*esamPubKeyIn)
	reqUpdateUser.UserDB = (*userIn)

	req, err = json.Marshal(reqUpdateUser)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqUpdateUser(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey, userOut *data.UserDB) error {
	var err error
	var reqUpdateUser reqUpdateUser

	err = json.Unmarshal(jsonIn[:], &reqUpdateUser)
	if err != nil {
		return err
	}

	if reqUpdateUser.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqUpdateUser.MsgHeader.SubType != ReqTypeUpdateUser {
		return errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqUpdateUser.ESAMPubKey
	(*userOut) = reqUpdateUser.UserDB

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Update */

/* ChangePassword */

type reqChangePassword struct {
	msgHeaderWrapper
	Password         string `json:"password"`
	PasswordHash     string `json:"password_hash"`
	PasswordHashSign []byte `json:"password_hash_sign"`
}

func BuildReqChangePassword(password string, passwordHash string, passwordHashSign []byte) ([]byte, error) {
	var err error
	var req []byte
	var reqChangePassword reqChangePassword

	reqChangePassword.MsgHeader.Type = MsgTypeRequest
	reqChangePassword.MsgHeader.SubType = ReqTypeChangePassword
	reqChangePassword.Password = password
	reqChangePassword.PasswordHash = passwordHash
	reqChangePassword.PasswordHashSign = passwordHashSign[:]

	req, err = json.Marshal(reqChangePassword)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqChangePassword(jsonIn []byte) (string, string, []byte, error) {
	var err error
	var reqChangePassword reqChangePassword

	err = json.Unmarshal(jsonIn[:], &reqChangePassword)
	if err != nil {
		return "", "", nil, err
	}

	if reqChangePassword.MsgHeader.Type != MsgTypeRequest {
		return "", "", nil, errors.New("Unexpected message type")
	}

	if reqChangePassword.MsgHeader.SubType != ReqTypeChangePassword {
		return "", "", nil, errors.New("Unexpected request type")
	}

	return reqChangePassword.Password, reqChangePassword.PasswordHash, reqChangePassword.PasswordHashSign[:], nil
}

/* ChangePassword */

/* List */

type reqListUsers struct {
	msgHeaderWrapper
	reqResultWrapper
	data.User `json:"filter"`
}

func BuildReqListUsers(userFilterIn *data.User) ([]byte, error) {
	var err error
	var req []byte
	var reqListUsers reqListUsers

	reqListUsers.MsgHeader.Type = MsgTypeRequest
	reqListUsers.MsgHeader.SubType = ReqTypeListUsers
	reqListUsers.User = (*userFilterIn)

	req, err = json.Marshal(reqListUsers)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqListUsers(jsonIn []byte, userFilterOut *data.User) error {
	var err error
	var reqListUsers reqListUsers

	err = json.Unmarshal(jsonIn[:], &reqListUsers)
	if err != nil {
		return err
	}

	if reqListUsers.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqListUsers.MsgHeader.SubType != ReqTypeListUsers {
		return errors.New("Unexpected request type")
	}

	if userFilterOut != nil {
		(*userFilterOut) = reqListUsers.User
	}

	return nil
}

type repListUsers struct {
	msgHeaderWrapper
	reqResultWrapper
	Users []data.UserDB `json:"users"`
}

func BuildRepListUsers(usersIn []data.UserDB) ([]byte, error) {
	var err error
	var rep []byte
	var repListUsers repListUsers

	repListUsers.MsgHeader.Type = MsgTypeReply
	repListUsers.MsgHeader.SubType = ReqTypeListUsers
	repListUsers.ReqResult.Status = ReqResultStatusSuccessful
	repListUsers.ReqResult.Reason = ReqResultReasonEmpty
	repListUsers.Users = usersIn[:]

	rep, err = json.Marshal(repListUsers)
	if err != nil {
		return nil, err
	}

	return rep[:], nil
}

func ParseRepListUsers(jsonIn []byte) ([]data.UserDB, error) {
	var err error
	var repListUsers repListUsers

	err = json.Unmarshal(jsonIn[:], &repListUsers)
	if err != nil {
		return nil, err
	}

	if repListUsers.MsgHeader.Type != MsgTypeReply {
		return nil, errors.New("Unexpected message type")
	}

	if repListUsers.MsgHeader.SubType != ReqTypeListUsers {
		return nil, errors.New("Unexpected request type")
	}

	err = repListUsers.ReqResult.Test()
	if err != nil {
		return nil, err
	}

	return repListUsers.Users[:], nil
}

/* List */

/* Get auth user data */

/* For build and parse request use BuildSimpleReq and ParseMsgHeader functions */

type repGetAuthUserData struct {
	msgHeaderWrapper
	reqResultWrapper
	User data.UserAuth `json:"auth_user_data"`
}

func BuildRepGetAuthUserData(userIn *data.UserAuth) ([]byte, error) {
	var err error
	var rep []byte
	var repGetAuthUserData repGetAuthUserData

	repGetAuthUserData.MsgHeader.Type = MsgTypeReply
	repGetAuthUserData.MsgHeader.SubType = ReqTypeGetAuthUserData
	repGetAuthUserData.ReqResult.Status = ReqResultStatusSuccessful
	repGetAuthUserData.ReqResult.Reason = ReqResultReasonEmpty
	repGetAuthUserData.User = (*userIn)

	rep, err = json.Marshal(repGetAuthUserData)
	if err != nil {
		return nil, err
	}

	return rep[:], nil
}

func ParseRepGetAuthUserData(jsonIn []byte, userOut *data.UserAuth) error {
	var err error
	var repGetAuthUserData repGetAuthUserData

	err = json.Unmarshal(jsonIn[:], &repGetAuthUserData)
	if err != nil {
		return err
	}

	if repGetAuthUserData.MsgHeader.Type != MsgTypeReply {
		return errors.New("Unexpected message type")
	}

	if repGetAuthUserData.MsgHeader.SubType != ReqTypeGetAuthUserData {
		return errors.New("Unexpected request type")
	}

	err = repGetAuthUserData.ReqResult.Test()
	if err != nil {
		return err
	}

	(*userOut) = repGetAuthUserData.User

	return nil
}

/* Get auth user data */

/* Del */

type reqDelUser struct {
	msgHeaderWrapper
	data.ESAMPubKey `json:"esam_pub_key"`
}

func BuildReqDelUser(esamPubKeyIn *data.ESAMPubKey) ([]byte, error) {
	var err error
	var req []byte
	var reqDelUser reqDelUser

	reqDelUser.MsgHeader.Type = MsgTypeRequest
	reqDelUser.MsgHeader.SubType = ReqTypeDelUser
	reqDelUser.ESAMPubKey = (*esamPubKeyIn)

	req, err = json.Marshal(reqDelUser)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqDelUser(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey) error {
	var err error
	var reqDelUser reqDelUser

	err = json.Unmarshal(jsonIn[:], &reqDelUser)
	if err != nil {
		return err
	}

	if reqDelUser.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqDelUser.MsgHeader.SubType != ReqTypeDelUser {
		return errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqDelUser.ESAMPubKey

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Del */
