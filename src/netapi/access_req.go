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
{ "msg": { "type": "request", "request": "add_access_req" }, "access_req": { "esam_pub_key": "", "subject": "", "name": "" }, "secret": "" }
{ "msg": { "type": "reply", "request": "add_access_req" }, "result": { "status": "failed", "reason": "" } }
{ "msg": { "type": "reply", "request": "add_access_req" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "list_access_reqs" }, "filter": { "esam_pub_key": "", "subject": "", "name": "", "addr": "", "time": "" } }
{ "msg": { "type": "reply", "request": "list_access_reqs" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "list_access_reqs" }, "result": { "status": "successful", "reason": "" }, "access_reqs": [ { "esam_pub_key": "", "subject": "", "name": "", "addr": "", "time": "" }, { "esam_pub_key": "", "subject": "", "name": "", "addr": "", "time": "" } ] }
*/

/*
{ "msg": { "type": "request", "request": "del_access_req" }, "esam_pub_key": "" }
{ "msg": { "type": "reply", "request": "del_access_req" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "del_access_req" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "del_access_req" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "del_access_req" }, "result": { "status": "successful", "reason": "" } }
*/

/* Add */

type reqAddAccessReq struct {
	msgHeaderWrapper
	data.AccessReq `json:"access_req"`
	Secret         string `json:"secret"`
}

func BuildReqAddAccessReq(accessReqIn *data.AccessReq, secret string) ([]byte, error) {
	var err error
	var req []byte
	var reqAddAccessReq reqAddAccessReq

	reqAddAccessReq.MsgHeader.Type = MsgTypeRequest
	reqAddAccessReq.MsgHeader.SubType = ReqTypeAddAccessReq
	reqAddAccessReq.AccessReq = (*accessReqIn)
	reqAddAccessReq.Secret = secret

	req, err = json.Marshal(reqAddAccessReq)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqAddAccessReq(jsonIn []byte, accessReqOut *data.AccessReq, secret *string) error {
	var err error
	var reqAddAccessReq reqAddAccessReq

	err = json.Unmarshal(jsonIn, &reqAddAccessReq)
	if err != nil {
		return err
	}

	if reqAddAccessReq.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqAddAccessReq.MsgHeader.SubType != ReqTypeAddAccessReq {
		return errors.New("Unexpected request type")
	}

	(*accessReqOut) = reqAddAccessReq.AccessReq
	(*secret) = reqAddAccessReq.Secret

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Add */

/* List */

type reqListAccessReqs struct {
	msgHeaderWrapper
	reqResultWrapper
	data.AccessReqDB `json:"filter"`
}

func BuildReqListAccessReqs(accessReqFilterIn *data.AccessReqDB) ([]byte, error) {
	var err error
	var req []byte
	var reqListAccessReqs reqListAccessReqs

	reqListAccessReqs.MsgHeader.Type = MsgTypeRequest
	reqListAccessReqs.MsgHeader.SubType = ReqTypeListAccessReqs
	reqListAccessReqs.AccessReqDB = (*accessReqFilterIn)

	req, err = json.Marshal(reqListAccessReqs)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqListAccessReqs(jsonIn []byte, accessReqFilterOut *data.AccessReqDB) error {
	var err error
	var reqListAccessReqs reqListAccessReqs

	err = json.Unmarshal(jsonIn, &reqListAccessReqs)
	if err != nil {
		return err
	}

	if reqListAccessReqs.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqListAccessReqs.MsgHeader.SubType != ReqTypeListAccessReqs {
		return errors.New("Unexpected request type")
	}

	if accessReqFilterOut != nil {
		(*accessReqFilterOut) = reqListAccessReqs.AccessReqDB
	}

	return nil
}

type repListAccessReqs struct {
	msgHeaderWrapper
	reqResultWrapper
	AccessReqs []data.AccessReqDB `json:"access_reqs"`
}

func BuildRepListAccessReqs(accessReqsIn []data.AccessReqDB) ([]byte, error) {
	var err error
	var rep []byte
	var repListAccessReqs repListAccessReqs

	repListAccessReqs.MsgHeader.Type = MsgTypeReply
	repListAccessReqs.MsgHeader.SubType = ReqTypeListAccessReqs
	repListAccessReqs.ReqResult.Status = ReqResultStatusSuccessful
	repListAccessReqs.ReqResult.Reason = ReqResultReasonEmpty
	repListAccessReqs.AccessReqs = accessReqsIn

	rep, err = json.Marshal(repListAccessReqs)
	if err != nil {
		return nil, err
	}

	return rep, nil
}

func ParseRepListAccessReqs(jsonIn []byte) ([]data.AccessReqDB, error) {
	var err error
	var repListAccessReqs repListAccessReqs

	err = json.Unmarshal(jsonIn, &repListAccessReqs)
	if err != nil {
		return nil, err
	}

	if repListAccessReqs.MsgHeader.Type != MsgTypeReply {
		return nil, errors.New("Unexpected message type")
	}

	if repListAccessReqs.MsgHeader.SubType != ReqTypeListAccessReqs {
		return nil, errors.New("Unexpected request type")
	}

	err = repListAccessReqs.ReqResult.Test()
	if err != nil {
		return nil, err
	}

	return repListAccessReqs.AccessReqs, nil
}

/* List */

/* Del */

type reqDelAccessReq struct {
	msgHeaderWrapper
	data.ESAMPubKey `json:"esam_pub_key"`
}

func BuildReqDelAccessReq(esamPubKeyIn *data.ESAMPubKey) ([]byte, error) {
	var err error
	var req []byte
	var reqDelAccessReq reqDelAccessReq

	reqDelAccessReq.MsgHeader.Type = MsgTypeRequest
	reqDelAccessReq.MsgHeader.SubType = ReqTypeDelAccessReq
	reqDelAccessReq.ESAMPubKey = (*esamPubKeyIn)

	req, err = json.Marshal(reqDelAccessReq)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqDelAccessReq(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey) error {
	var err error
	var reqDelAccessReq reqDelAccessReq

	err = json.Unmarshal(jsonIn, &reqDelAccessReq)
	if err != nil {
		return err
	}

	if reqDelAccessReq.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqDelAccessReq.MsgHeader.SubType != ReqTypeDelAccessReq {
		return errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqDelAccessReq.ESAMPubKey

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Del */
