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
{ "item1": "value1" }
{ "reply": "Unsupported message" }
*/

/*
{ "msg": { "type": "request", "request": "blablabla" }, "data": { "item1": "value1", "item2": "value2" } }
{ "msg": { "type": "reply", "request": "blablabla" }, "result": { "status": "failed", "reason": "Unsupported request" } }
*/

/*
{ "msg": { "type": "notice", "subtype": "noop" } }
{ "msg": { "type": "notice", "subtype": "updated_users" } }
{ "msg": { "type": "notice", "subtype": "updated_nodes" } }
*/

type MsgHeader struct {
	Type    string `json:"type"`
	SubType string `json:"subtype"`
}

type msgHeaderWrapper struct {
	MsgHeader `json:"msg"`
}

type ReqResult struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type reqResultWrapper struct {
	ReqResult `json:"result"`
}

const (
	MsgTypeRequest = "request"
	MsgTypeReply   = "reply"
	MsgTypeNotice  = "notice"
)

const (
	ReqTypeAddAccessReq = "add_access_req"

	ReqTypeAuth = "auth"

	ReqTypeListAccessReqs = "list_access_reqs"
	ReqTypeDelAccessReq   = "del_access_req"

	ReqTypeAddUser         = "add_user"
	ReqTypeUpdateUser      = "update_user"
	ReqTypeChangePassword  = "change_password"
	ReqTypeListUsers       = "list_user"
	ReqTypeGetAuthUserData = "get_auth_user_data"
	ReqTypeDelUser         = "del_user"

	ReqTypeAddNode          = "add_node"
	ReqTypeUpdateNode       = "update_node"
	ReqTypeListNodes        = "list_nodes"
	ReqTypeFindInNodesCache = "find_in_nodes_cache"
	ReqTypeDelNode          = "del_node"

	ReqTypeGetDirConnSettings = "get_dir_conn_settings"
	ReqTypePassKeyPassword    = "pass_key_password"
)

const (
	ReqResultStatusFailed     = "failed"
	ReqResultStatusSuccessful = "successful"
)

const (
	ReqResultReasonEmpty               = ""
	ReqResultReasonUnsupportedReq      = "Unsupported request"
	ReqResultReasonInvalidInputData    = "Invalid input data"
	ReqResultReasonInternalError       = "Internal error"
	ReqResultReasonAccessDenied        = "Access denied"
	ReqResultReasonInvalidSignature    = "Invalid signature"
	ReqResultReasonAlreadyExist        = "Already exist"
	ReqResultReasonNotFound            = "Not found"
	ReqResultReasonPasswordTooSimple   = "Password too simple"
	ReqResultReasonKeyPasswordRequired = "Key password required"
)

const (
	NoticeTypeNoop         = "noop"
	NoticeTypeUpdatedUsers = "updated_users"
	NoticeTypeUpdatedNodes = "updated_nodes"
)

func TestMsgType(msgType string) error {
	switch msgType {
	case MsgTypeRequest:
	case MsgTypeReply:
	case MsgTypeNotice:

	default:
		return errors.New("Unsupported message type")
	}

	return nil
}

func TestReqType(requestType string) error {
	switch requestType {
	case ReqTypeAddAccessReq:

	case ReqTypeAuth:

	case ReqTypeListAccessReqs:
	case ReqTypeDelAccessReq:

	case ReqTypeAddUser:
	case ReqTypeUpdateUser:
	case ReqTypeChangePassword:
	case ReqTypeListUsers:
	case ReqTypeGetAuthUserData:
	case ReqTypeDelUser:

	case ReqTypeAddNode:
	case ReqTypeUpdateNode:
	case ReqTypeListNodes:
	case ReqTypeFindInNodesCache:
	case ReqTypeDelNode:

	case ReqTypeGetDirConnSettings:
	case ReqTypePassKeyPassword:

	default:
		return errors.New("Unsupported request")
	}

	return nil
}

func TestNoticeType(noticeType string) error {
	switch noticeType {
	case NoticeTypeNoop:
	case NoticeTypeUpdatedUsers:
	case NoticeTypeUpdatedNodes:

	default:
		return errors.New("Unsupported notice")
	}

	return nil
}

func TestMsgSubType(subType string) error {
	var (
		errReqType    error
		errNoticeType error
	)

	errReqType = TestReqType(subType)
	errNoticeType = TestNoticeType(subType)
	if errReqType != nil && errNoticeType != nil {
		if errReqType != nil {
			return errReqType
		}
		if errNoticeType != nil {
			return errNoticeType
		}
	}

	return nil
}

func (msgHeader *MsgHeader) Test() error {
	var err error

	err = TestMsgType(msgHeader.Type)
	if err != nil {
		return err
	}

	err = TestMsgSubType(msgHeader.SubType)
	if err != nil {
		return err
	}

	return nil
}

func TestReqResultStatus(reqResultStatus string) error {
	switch reqResultStatus {
	case ReqResultStatusFailed:
	case ReqResultStatusSuccessful:

	default:
		return errors.New("Unsupported request result status")
	}

	return nil
}

func (reqResult *ReqResult) Test() error {
	var err error

	err = TestReqResultStatus(reqResult.Status)
	if err != nil {
		return err
	}

	return nil
}

func ParseMsgHeader(jsonIn []byte, msgHeaderOut *MsgHeader) error {
	var (
		err              error
		msgHeaderWrapper msgHeaderWrapper
	)

	err = json.Unmarshal(jsonIn, &msgHeaderWrapper)
	if err != nil {
		return err
	}

	err = msgHeaderWrapper.MsgHeader.Test()
	if err != nil {
		return err
	}

	(*msgHeaderOut) = msgHeaderWrapper.MsgHeader

	return nil
}

func ParseReqResult(jsonIn []byte, reqResultOut *ReqResult) error {
	var (
		err              error
		reqResultWrapper reqResultWrapper
	)

	err = json.Unmarshal(jsonIn, &reqResultWrapper)
	if err != nil {
		return err
	}

	err = reqResultWrapper.ReqResult.Test()
	if err != nil {
		return err
	}

	(*reqResultOut) = reqResultWrapper.ReqResult

	return nil
}

/* Unsupported message */

type simpleReply struct {
	Reply string `json:"reply"`
}

func BuildUnsupportedMsg() ([]byte, error) {
	var (
		err         error
		reply       []byte
		simpleReply simpleReply
	)

	simpleReply.Reply = "Unsupported message"

	reply, err = json.Marshal(simpleReply)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

/* Unsupported message */

/* Universal */

/*
Suitable for:
 - ReqTypeGetDirConnSettings
 - ReqTypeGetAuthUserData
*/
/* For parse request use ParseMsgHeader */
func BuildSimpleReq(reqType string) ([]byte, error) {
	var (
		err              error
		req              []byte
		msgHeaderWrapper msgHeaderWrapper
	)

	err = TestReqType(reqType)
	if err != nil {
		return nil, err
	}

	msgHeaderWrapper.MsgHeader.Type = MsgTypeRequest
	msgHeaderWrapper.MsgHeader.SubType = reqType

	req, err = json.Marshal(msgHeaderWrapper)
	if err != nil {
		return nil, err
	}

	return req, nil
}

/*
Suitable for:
 - Unsupported request
 - ReqTypeAddAccessReq
 - ReqTypeDelAccessReq
 - ReqTypeAuth
 - ReqTypeAddUser
 - ReqTypeUpdateUser
 - ReqTypeChangePassword
 - ReqTypeDelUser
 - ReqTypeAddNode
 - ReqTypeUpdateNode
 - ReqTypeDelNode
 - ReqTypePassKeyPassword
*/
/* For parse request use ParseReqResult */
type repReqResult struct {
	msgHeaderWrapper
	reqResultWrapper
}

func BuildSimpleRep(reqType string, reqResultIn *ReqResult) ([]byte, error) {
	var (
		err          error
		rep          []byte
		repReqResult repReqResult
	)

	err = TestReqType(reqType)
	if err != nil {
		return nil, err
	}

	err = reqResultIn.Test()
	if err != nil {
		return nil, err
	}

	repReqResult.MsgHeader.Type = MsgTypeReply
	repReqResult.MsgHeader.SubType = reqType
	repReqResult.ReqResult = (*reqResultIn)

	rep, err = json.Marshal(repReqResult)
	if err != nil {
		return nil, err
	}

	return rep, nil
}

/* Universal */

/* Notices */

/* For parse notice use ParseMsgHeader */
func BuildNotice(noticeType string) ([]byte, error) {
	var (
		err              error
		notice           []byte
		msgHeaderWrapper msgHeaderWrapper
	)

	err = TestNoticeType(noticeType)
	if err != nil {
		return nil, err
	}

	msgHeaderWrapper.MsgHeader.Type = MsgTypeNotice
	msgHeaderWrapper.MsgHeader.SubType = noticeType

	notice, err = json.Marshal(msgHeaderWrapper)
	if err != nil {
		return nil, err
	}

	return notice, nil
}

/* Notices */
