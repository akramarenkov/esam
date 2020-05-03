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

/*
{ "msg": { "type": "reply", "request": "" }, "result": { "status": "failed", "reason": "Key password required" } }
{ "msg": { "type": "request", "request": "pass_key_password" }, "password": "" }
{ "msg": { "type": "reply", "request": "pass_key_password" }, "result": { "status": "successful", "reason": "" } }
{ "msg": { "type": "reply", "request": "pass_key_password" }, "result": { "status": "successful", "reason": "Invalid input data" } }
*/

type reqPassKeyPassword struct {
	msgHeaderWrapper
	Password string `json:"password"`
}

func BuildReqPassKeyPassword(password string) ([]byte, error) {
	var err error
	var req []byte
	var reqPassKeyPassword reqPassKeyPassword

	reqPassKeyPassword.MsgHeader.Type = MsgTypeRequest
	reqPassKeyPassword.MsgHeader.SubType = ReqTypePassKeyPassword
	reqPassKeyPassword.Password = password

	req, err = json.Marshal(reqPassKeyPassword)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqPassKeyPassword(jsonIn []byte) (string, error) {
	var err error
	var reqPassKeyPassword reqPassKeyPassword

	err = json.Unmarshal(jsonIn[:], &reqPassKeyPassword)
	if err != nil {
		return "", err
	}

	if reqPassKeyPassword.MsgHeader.Type != MsgTypeRequest {
		return "", errors.New("Unexpected message type")
	}

	if reqPassKeyPassword.MsgHeader.SubType != ReqTypePassKeyPassword {
		return "", errors.New("Unexpected request type")
	}

	return reqPassKeyPassword.Password, nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */
