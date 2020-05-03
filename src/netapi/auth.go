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
Stage one
{ "msg": { "type": "request", "request": "auth" }, "esam_pub_key": "", "notices_not_required": "" }
{ "msg": { "type": "reply", "request": "auth" }, "result": { "status": "failed", "reason": "" } }
{ "msg": { "type": "reply", "request": "auth" }, "result": { "status": "successful", "reason": "" }, "question": "" }

Stage two
{ "msg": { "type": "request", "request": "auth" }, "answer": "" }
{ "msg": { "type": "reply", "request": "auth" }, "result": { "status": "failed", "reason": "" } }
{ "msg": { "type": "reply", "request": "auth" }, "result": { "status": "successful", "reason": "" } }
*/

type reqAuthStageOne struct {
	msgHeaderWrapper
	data.ESAMPubKey    `json:"esam_pub_key"`
	NoticesNotRequired bool `json:"notices_not_required"`
}

type repAuthStageOne struct {
	msgHeaderWrapper
	reqResultWrapper
	Question []byte `json:"question"`
}

type reqAuthStageTwo struct {
	msgHeaderWrapper
	Answer []byte `json:"answer"`
}

func BuildReqAuthStageOne(esamPubKeyIn *data.ESAMPubKey, noticesNotRequired bool) ([]byte, error) {
	var err error
	var req []byte
	var reqAuthStageOne reqAuthStageOne

	if esamPubKeyIn == nil {
		return nil, errors.New("ESAM pub key is not defined")
	}

	reqAuthStageOne.MsgHeader.Type = MsgTypeRequest
	reqAuthStageOne.MsgHeader.SubType = ReqTypeAuth
	reqAuthStageOne.ESAMPubKey = (*esamPubKeyIn)
	reqAuthStageOne.NoticesNotRequired = noticesNotRequired

	req, err = json.Marshal(reqAuthStageOne)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqAuthStageOne(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey) (bool, error) {
	var err error
	var reqAuthStageOne reqAuthStageOne

	if esamPubKeyOut == nil {
		return false, errors.New("ESAM pub key variable is not defined")
	}

	err = json.Unmarshal(jsonIn[:], &reqAuthStageOne)
	if err != nil {
		return false, err
	}

	if reqAuthStageOne.MsgHeader.Type != MsgTypeRequest {
		return false, errors.New("Unexpected message type")
	}

	if reqAuthStageOne.MsgHeader.SubType != ReqTypeAuth {
		return false, errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqAuthStageOne.ESAMPubKey

	return reqAuthStageOne.NoticesNotRequired, nil
}

func BuildRepAuthStageOne(questionIn []byte) ([]byte, error) {
	var err error
	var rep []byte
	var repAuthStageOne repAuthStageOne

	repAuthStageOne.MsgHeader.Type = MsgTypeReply
	repAuthStageOne.MsgHeader.SubType = ReqTypeAuth
	repAuthStageOne.ReqResult.Status = ReqResultStatusSuccessful
	repAuthStageOne.ReqResult.Reason = ReqResultReasonEmpty
	repAuthStageOne.Question = questionIn[:]

	rep, err = json.Marshal(repAuthStageOne)
	if err != nil {
		return nil, err
	}

	return rep[:], nil
}

func ParseRepAuthStageOne(jsonIn []byte) ([]byte, error) {
	var err error
	var repAuthStageOne repAuthStageOne

	err = json.Unmarshal(jsonIn[:], &repAuthStageOne)
	if err != nil {
		return nil, err
	}

	if repAuthStageOne.MsgHeader.Type != MsgTypeReply {
		return nil, errors.New("Unexpected message type")
	}

	if repAuthStageOne.MsgHeader.SubType != ReqTypeAuth {
		return nil, errors.New("Unexpected request type")
	}

	err = repAuthStageOne.ReqResult.Test()
	if err != nil {
		return nil, err
	}

	return repAuthStageOne.Question[:], nil
}

func BuildReqAuthStageTwo(answerIn []byte) ([]byte, error) {
	var err error
	var req []byte
	var reqAuthStageTwo reqAuthStageTwo

	if len(answerIn[:]) == 0 {
		return nil, errors.New("Answer is not defined")
	}

	reqAuthStageTwo.MsgHeader.Type = MsgTypeRequest
	reqAuthStageTwo.MsgHeader.SubType = ReqTypeAuth
	reqAuthStageTwo.Answer = answerIn[:]

	req, err = json.Marshal(reqAuthStageTwo)
	if err != nil {
		return nil, err
	}

	return req[:], nil
}

func ParseReqAuthStageTwo(jsonIn []byte) ([]byte, error) {
	var err error
	var reqAuthStageTwo reqAuthStageTwo

	err = json.Unmarshal(jsonIn[:], &reqAuthStageTwo)
	if err != nil {
		return nil, err
	}

	if reqAuthStageTwo.MsgHeader.Type != MsgTypeRequest {
		return nil, errors.New("Unexpected message type")
	}

	if reqAuthStageTwo.MsgHeader.SubType != ReqTypeAuth {
		return nil, errors.New("Unexpected request type")
	}

	return reqAuthStageTwo.Answer[:], nil
}

/* For build and parse reply in stage two use BuildSimpleRep and ParseReqResult functions */
