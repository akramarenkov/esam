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
{ "msg": { "type": "request", "request": "add_node" }, "node": { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "esam_pub_key_sign": "", "name_sign": "", "ssh_addr_sign": "", "ssh_port_sign": "", "sign_subject": "" } }
{ "msg": { "type": "reply", "request": "add_node" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "add_node" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "add_node" }, "result": { "status": "failed", "reason": "Invalid signature" } }
{ "msg": { "type": "reply", "request": "add_node" }, "result": { "status": "failed", "reason": "Already exist" } }
{ "msg": { "type": "reply", "request": "add_node" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "update_node" }, "esam_pub_key": "", "node": { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "esam_pub_key_sign": "", "name_sign": "", "ssh_addr_sign": "", "ssh_port_sign": "", "sign_subject": "" } }
{ "msg": { "type": "reply", "request": "update_node" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "update_node" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "update_node" }, "result": { "status": "failed", "reason": "Invalid signature" } }
{ "msg": { "type": "reply", "request": "update_node" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "update_node" }, "result": { "status": "successful", "reason": "" } }
*/

/*
{ "msg": { "type": "request", "request": "list_nodes" }, "filter": { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "" } }
{ "msg": { "type": "reply", "request": "list_nodes" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "list_nodes" }, "result": { "status": "successful", "reason": "" }, "nodes": [ { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "esam_pub_key_sign": "", "name_sign": "", "ssh_addr_sign": "", "ssh_port_sign": "", "sign_subject": "" }, { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "esam_pub_key_sign": "", "name_sign": "", "ssh_addr_sign": "", "ssh_port_sign": "", "sign_subject": "" } ] }
*/

/*
{ "msg": { "type": "request", "request": "find_in_nodes_cache" }, "filter": { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "trusted_data": "" }, "full_match": "" }
{ "msg": { "type": "reply", "request": "del_node" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "find_in_nodes_cache" }, "result": { "status": "successful", "reason": "" }, "nodes": [ { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "trusted_data": "" }, { "esam_pub_key": "", "name": "", "ssh_addr": "", "ssh_port": "", "trusted_data": "" } ] }
*/

/*
{ "msg": { "type": "request", "request": "del_node" }, "esam_pub_key": "" }
{ "msg": { "type": "reply", "request": "del_node" }, "result": { "status": "failed", "reason": "Internal error" } }
{ "msg": { "type": "reply", "request": "del_node" }, "result": { "status": "failed", "reason": "Access denied" } }
{ "msg": { "type": "reply", "request": "del_node" }, "result": { "status": "failed", "reason": "Not found" } }
{ "msg": { "type": "reply", "request": "del_node" }, "result": { "status": "successful", "reason": "" } }
*/

/* Add */

type reqAddNode struct {
	msgHeaderWrapper
	data.NodeDB `json:"node"`
}

func BuildReqAddNode(nodeIn *data.NodeDB) ([]byte, error) {
	var (
		err        error
		req        []byte
		reqAddNode reqAddNode
	)

	reqAddNode.MsgHeader.Type = MsgTypeRequest
	reqAddNode.MsgHeader.SubType = ReqTypeAddNode
	reqAddNode.NodeDB = (*nodeIn)

	req, err = json.Marshal(reqAddNode)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqAddNode(jsonIn []byte, nodeOut *data.NodeDB) error {
	var (
		err        error
		reqAddNode reqAddNode
	)

	err = json.Unmarshal(jsonIn, &reqAddNode)
	if err != nil {
		return err
	}

	if reqAddNode.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqAddNode.MsgHeader.SubType != ReqTypeAddNode {
		return errors.New("Unexpected request type")
	}

	(*nodeOut) = reqAddNode.NodeDB

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Add */

/* Update */

type reqUpdateNode struct {
	msgHeaderWrapper
	data.ESAMPubKey `json:"esam_pub_key"`
	data.NodeDB     `json:"node"`
}

func BuildReqUpdateNode(esamPubKeyIn *data.ESAMPubKey, nodeIn *data.NodeDB) ([]byte, error) {
	var (
		err           error
		req           []byte
		reqUpdateNode reqUpdateNode
	)

	reqUpdateNode.MsgHeader.Type = MsgTypeRequest
	reqUpdateNode.MsgHeader.SubType = ReqTypeUpdateNode
	reqUpdateNode.ESAMPubKey = (*esamPubKeyIn)
	reqUpdateNode.NodeDB = (*nodeIn)

	req, err = json.Marshal(reqUpdateNode)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqUpdateNode(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey, nodeOut *data.NodeDB) error {
	var (
		err           error
		reqUpdateNode reqUpdateNode
	)

	err = json.Unmarshal(jsonIn, &reqUpdateNode)
	if err != nil {
		return err
	}

	if reqUpdateNode.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqUpdateNode.MsgHeader.SubType != ReqTypeUpdateNode {
		return errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqUpdateNode.ESAMPubKey
	(*nodeOut) = reqUpdateNode.NodeDB

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Update */

/* List */

type reqListNodes struct {
	msgHeaderWrapper
	reqResultWrapper
	data.Node `json:"filter"`
}

func BuildReqListNodes(nodeFilterIn *data.Node) ([]byte, error) {
	var (
		err          error
		req          []byte
		reqListNodes reqListNodes
	)

	reqListNodes.MsgHeader.Type = MsgTypeRequest
	reqListNodes.MsgHeader.SubType = ReqTypeListNodes
	reqListNodes.Node = (*nodeFilterIn)

	req, err = json.Marshal(reqListNodes)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqListNodes(jsonIn []byte, nodeFilterOut *data.Node) error {
	var (
		err          error
		reqListNodes reqListNodes
	)

	err = json.Unmarshal(jsonIn, &reqListNodes)
	if err != nil {
		return err
	}

	if reqListNodes.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqListNodes.MsgHeader.SubType != ReqTypeListNodes {
		return errors.New("Unexpected request type")
	}

	if nodeFilterOut != nil {
		(*nodeFilterOut) = reqListNodes.Node
	}

	return nil
}

type repListNodes struct {
	msgHeaderWrapper
	reqResultWrapper
	Nodes []data.NodeDB `json:"nodes"`
}

func BuildRepListNodes(nodesIn []data.NodeDB) ([]byte, error) {
	var (
		err          error
		rep          []byte
		repListNodes repListNodes
	)

	repListNodes.MsgHeader.Type = MsgTypeReply
	repListNodes.MsgHeader.SubType = ReqTypeListNodes
	repListNodes.ReqResult.Status = ReqResultStatusSuccessful
	repListNodes.ReqResult.Reason = ReqResultReasonEmpty
	repListNodes.Nodes = nodesIn

	rep, err = json.Marshal(repListNodes)
	if err != nil {
		return nil, err
	}

	return rep, nil
}

func ParseRepListNodes(jsonIn []byte) ([]data.NodeDB, error) {
	var (
		err          error
		repListNodes repListNodes
	)

	err = json.Unmarshal(jsonIn, &repListNodes)
	if err != nil {
		return nil, err
	}

	if repListNodes.MsgHeader.Type != MsgTypeReply {
		return nil, errors.New("Unexpected message type")
	}

	if repListNodes.MsgHeader.SubType != ReqTypeListNodes {
		return nil, errors.New("Unexpected request type")
	}

	err = repListNodes.ReqResult.Test()
	if err != nil {
		return nil, err
	}

	return repListNodes.Nodes, nil
}

/* List */

/* Find in nodes cache*/

type reqFindInNodesCache struct {
	msgHeaderWrapper
	reqResultWrapper
	data.NodeAuth `json:"filter"`
	FullMatch     bool `json:"full_match"`
}

func BuildReqFindInNodesCache(nodeFilterIn *data.NodeAuth, fullMatch bool) ([]byte, error) {
	var (
		err                 error
		req                 []byte
		reqFindInNodesCache reqFindInNodesCache
	)

	reqFindInNodesCache.MsgHeader.Type = MsgTypeRequest
	reqFindInNodesCache.MsgHeader.SubType = ReqTypeFindInNodesCache
	reqFindInNodesCache.NodeAuth = (*nodeFilterIn)
	reqFindInNodesCache.FullMatch = fullMatch

	req, err = json.Marshal(reqFindInNodesCache)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqFindInNodesCache(jsonIn []byte, nodeFilterOut *data.NodeAuth, fullMatchOut *bool) error {
	var err error
	var reqFindInNodesCache reqFindInNodesCache

	err = json.Unmarshal(jsonIn, &reqFindInNodesCache)
	if err != nil {
		return err
	}

	if reqFindInNodesCache.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqFindInNodesCache.MsgHeader.SubType != ReqTypeFindInNodesCache {
		return errors.New("Unexpected request type")
	}

	if nodeFilterOut != nil {
		(*nodeFilterOut) = reqFindInNodesCache.NodeAuth
	}

	if fullMatchOut != nil {
		(*fullMatchOut) = reqFindInNodesCache.FullMatch
	}

	return nil
}

type repFindInNodesCache struct {
	msgHeaderWrapper
	reqResultWrapper
	Nodes []data.NodeAuth `json:"nodes"`
}

func BuildRepFindInNodesCache(nodesIn []data.NodeAuth) ([]byte, error) {
	var err error
	var rep []byte
	var repFindInNodesCache repFindInNodesCache

	repFindInNodesCache.MsgHeader.Type = MsgTypeReply
	repFindInNodesCache.MsgHeader.SubType = ReqTypeFindInNodesCache
	repFindInNodesCache.ReqResult.Status = ReqResultStatusSuccessful
	repFindInNodesCache.ReqResult.Reason = ReqResultReasonEmpty
	repFindInNodesCache.Nodes = nodesIn

	rep, err = json.Marshal(repFindInNodesCache)
	if err != nil {
		return nil, err
	}

	return rep, nil
}

func ParseRepFindInNodesCache(jsonIn []byte) ([]data.NodeAuth, error) {
	var err error
	var repFindInNodesCache repFindInNodesCache

	err = json.Unmarshal(jsonIn, &repFindInNodesCache)
	if err != nil {
		return nil, err
	}

	if repFindInNodesCache.MsgHeader.Type != MsgTypeReply {
		return nil, errors.New("Unexpected message type")
	}

	if repFindInNodesCache.MsgHeader.SubType != ReqTypeFindInNodesCache {
		return nil, errors.New("Unexpected request type")
	}

	err = repFindInNodesCache.ReqResult.Test()
	if err != nil {
		return nil, err
	}

	return repFindInNodesCache.Nodes, nil
}

/* Find in nodes cache */

/* Del */

type reqDelNode struct {
	msgHeaderWrapper
	data.ESAMPubKey `json:"esam_pub_key"`
}

func BuildReqDelNode(esamPubKeyIn *data.ESAMPubKey) ([]byte, error) {
	var err error
	var req []byte
	var reqDelNode reqDelNode

	reqDelNode.MsgHeader.Type = MsgTypeRequest
	reqDelNode.MsgHeader.SubType = ReqTypeDelNode
	reqDelNode.ESAMPubKey = (*esamPubKeyIn)

	req, err = json.Marshal(reqDelNode)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func ParseReqDelNode(jsonIn []byte, esamPubKeyOut *data.ESAMPubKey) error {
	var err error
	var reqDelNode reqDelNode

	err = json.Unmarshal(jsonIn, &reqDelNode)
	if err != nil {
		return err
	}

	if reqDelNode.MsgHeader.Type != MsgTypeRequest {
		return errors.New("Unexpected message type")
	}

	if reqDelNode.MsgHeader.SubType != ReqTypeDelNode {
		return errors.New("Unexpected request type")
	}

	(*esamPubKeyOut) = reqDelNode.ESAMPubKey

	return nil
}

/* For build and parse reply use BuildSimpleRep and ParseReqResult functions */

/* Del */
