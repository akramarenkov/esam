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

package requests

import (
	"crypto/rsa"
	"errors"
	"net"
	"time"
)

import (
	"esam/src/crypt"
	"esam/src/data"
	"esam/src/netapi"
	"esam/src/netmsg"
)

func SendAccessReq(conn net.Conn, accessReqIn *data.AccessReq, secret string, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqAddAccessReq(accessReqIn, secret)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeAddAccessReq {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func Auth(conn net.Conn, esamPubKey *data.ESAMPubKey, key *rsa.PrivateKey, noticesNotRequired bool, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	var authQuestionEncrypted []byte
	var authQuestion []byte

	msgOut, err = netapi.BuildReqAuthStageOne(esamPubKey, noticesNotRequired)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	switch msgInHeader.Type {
	case netapi.MsgTypeReply:
		{
			switch msgInHeader.SubType {
			case netapi.ReqTypeAuth:
				{

					err = netapi.ParseReqResult(msgIn, &msgInReqResult)
					if err != nil {
						return err
					}

					switch msgInReqResult.Status {
					case netapi.ReqResultStatusFailed:
						{
							return errors.New(msgInReqResult.Reason)
						}

					case netapi.ReqResultStatusSuccessful:
						{
							authQuestionEncrypted, err = netapi.ParseRepAuthStageOne(msgIn[:])
							if err != nil {
								return err
							}

							authQuestion, err = crypt.Decrypt(authQuestionEncrypted[:], key)
							if err != nil {
								return err
							}

							msgOut, err = netapi.BuildReqAuthStageTwo(authQuestion[:])
							if err != nil {
								return err
							}

							_, err = netmsg.Send(conn, msgOut[:], netTimeout)
							if err != nil {
								return err
							}

							msgIn, err = netmsg.Recv(conn, netTimeout)
							if err != nil {
								return err
							}

							err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
							if err != nil {
								return err
							}

							switch msgInHeader.Type {
							case netapi.MsgTypeReply:
								{
									switch msgInHeader.SubType {
									case netapi.ReqTypeAuth:
										{
											err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
											if err != nil {
												return err
											}

											switch msgInReqResult.Status {
											case netapi.ReqResultStatusFailed:
												{
													return errors.New(msgInReqResult.Reason)
												}

											case netapi.ReqResultStatusSuccessful:
												{
													return nil
												}

											default:
												{
													return errors.New("Unsupported at this stage request result status was received")
												}
											}
										}

									default:
										{
											return errors.New("Unsupported at this stage reply was received")
										}
									}
								}

							default:
								{
									return errors.New("Unsupported message was received")
								}
							}
						}

					default:
						{
							return errors.New("Unsupported at this stage request result status was received")
						}
					}
				}

			default:
				{
					return errors.New("Unsupported at this stage reply was received")
				}
			}
		}

	default:
		{
			return errors.New("Unsupported message was received")
		}
	}

	return errors.New("Unknown error")
}

func ListAccessReqs(conn net.Conn, accessReqFilterIn *data.AccessReqDB, netTimeout time.Duration) ([]data.AccessReqDB, error) {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult
	var accessReqOut []data.AccessReqDB

	msgOut, err = netapi.BuildReqListAccessReqs(accessReqFilterIn)
	if err != nil {
		return nil, err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return nil, err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return nil, err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return nil, err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return nil, errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeListAccessReqs {
		return nil, errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return nil, err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return nil, errors.New(msgInReqResult.Reason)
	}

	accessReqOut, err = netapi.ParseRepListAccessReqs(msgIn[:])
	if err != nil {
		return nil, err
	}

	return accessReqOut[:], nil
}

func DelAccessReq(conn net.Conn, esamPubKey *data.ESAMPubKey, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqDelAccessReq(esamPubKey)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeDelAccessReq {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func AddUser(conn net.Conn, userIn *data.UserDB, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqAddUser(userIn)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeAddUser {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func UpdateUser(conn net.Conn, esamPubKey *data.ESAMPubKey, userIn *data.UserDB, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqUpdateUser(esamPubKey, userIn)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeUpdateUser {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func ChangePassword(conn net.Conn, password string, passwordHash string, passwordHashSign []byte, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqChangePassword(password, passwordHash, passwordHashSign)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeChangePassword {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func ListUsers(conn net.Conn, userFilterIn *data.User, netTimeout time.Duration) ([]data.UserDB, error) {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult
	var userFilter data.User
	var usersOut []data.UserDB

	if userFilterIn != nil {
		userFilter = (*userFilterIn)
	}

	msgOut, err = netapi.BuildReqListUsers(&userFilter)
	if err != nil {
		return nil, err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return nil, err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return nil, err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return nil, err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return nil, errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeListUsers {
		return nil, errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return nil, err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return nil, errors.New(msgInReqResult.Reason)
	}

	usersOut, err = netapi.ParseRepListUsers(msgIn[:])
	if err != nil {
		return nil, err
	}

	return usersOut[:], nil
}

func GetAuthUserData(conn net.Conn, userOut *data.UserAuth, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	var userTmp data.UserAuth

	msgOut, err = netapi.BuildSimpleReq(netapi.ReqTypeGetAuthUserData)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeGetAuthUserData {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	err = netapi.ParseRepGetAuthUserData(msgIn[:], &userTmp)
	if err != nil {
		return err
	}

	(*userOut) = userTmp

	return nil
}

func DelUser(conn net.Conn, esamPubKey *data.ESAMPubKey, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqDelUser(esamPubKey)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeDelUser {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func AddNode(conn net.Conn, nodeIn *data.NodeDB, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqAddNode(nodeIn)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeAddNode {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func UpdateNode(conn net.Conn, esamPubKey *data.ESAMPubKey, nodeIn *data.NodeDB, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqUpdateNode(esamPubKey, nodeIn)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeUpdateNode {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func ListNodes(conn net.Conn, nodeFilterIn *data.Node, netTimeout time.Duration) ([]data.NodeDB, error) {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult
	var nodeFilter data.Node
	var nodesOut []data.NodeDB

	if nodeFilterIn != nil {
		nodeFilter = (*nodeFilterIn)
	}

	msgOut, err = netapi.BuildReqListNodes(&nodeFilter)
	if err != nil {
		return nil, err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return nil, err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return nil, err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return nil, err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return nil, errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeListNodes {
		return nil, errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return nil, err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return nil, errors.New(msgInReqResult.Reason)
	}

	nodesOut, err = netapi.ParseRepListNodes(msgIn[:])
	if err != nil {
		return nil, err
	}

	return nodesOut[:], nil
}

func FindInNodesCache(conn net.Conn, nodeFilterIn *data.NodeAuth, fullMatch bool, netTimeout time.Duration) ([]data.NodeAuth, error) {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult
	var nodeFilter data.NodeAuth
	var nodesOut []data.NodeAuth

	if nodeFilterIn != nil {
		nodeFilter = (*nodeFilterIn)
	}

	msgOut, err = netapi.BuildReqFindInNodesCache(&nodeFilter, fullMatch)
	if err != nil {
		return nil, err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return nil, err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return nil, err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return nil, err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return nil, errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeFindInNodesCache {
		return nil, errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return nil, err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return nil, errors.New(msgInReqResult.Reason)
	}

	nodesOut, err = netapi.ParseRepFindInNodesCache(msgIn[:])
	if err != nil {
		return nil, err
	}

	return nodesOut[:], nil
}

func DelNode(conn net.Conn, esamPubKey *data.ESAMPubKey, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqDelNode(esamPubKey)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeDelNode {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}

func GetDirConnSettings(conn net.Conn, dirConnSettingsOut *data.DirConnSettings, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	var dirConnSettingsTmp data.DirConnSettings

	msgOut, err = netapi.BuildSimpleReq(netapi.ReqTypeGetDirConnSettings)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypeGetDirConnSettings {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	err = netapi.ParseRepGetDirConnSettings(msgIn[:], &dirConnSettingsTmp)
	if err != nil {
		return err
	}

	(*dirConnSettingsOut) = dirConnSettingsTmp

	return nil
}

func PassKeyPassword(conn net.Conn, password string, netTimeout time.Duration) error {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader
	var msgInReqResult netapi.ReqResult

	msgOut, err = netapi.BuildReqPassKeyPassword(password)
	if err != nil {
		return err
	}

	_, err = netmsg.Send(conn, msgOut[:], netTimeout)
	if err != nil {
		return err
	}

	msgIn, err = netmsg.Recv(conn, netTimeout)
	if err != nil {
		return err
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		return err
	}

	if msgInHeader.Type != netapi.MsgTypeReply {
		return errors.New("Message type does not match expected")
	}

	if msgInHeader.SubType != netapi.ReqTypePassKeyPassword {
		return errors.New("Request type does not match expected")
	}

	err = netapi.ParseReqResult(msgIn[:], &msgInReqResult)
	if err != nil {
		return err
	}

	if msgInReqResult.Status != netapi.ReqResultStatusSuccessful {
		return errors.New(msgInReqResult.Reason)
	}

	return nil
}
